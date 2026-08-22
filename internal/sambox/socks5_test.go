// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sambox

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// startSOCKS5 serves s on a Unix socket, the transport the sandbox boundary
// actually uses, and returns its path.
func startSOCKS5(t *testing.T, s *SOCKS5Server) string {
	t.Helper()

	// Not t.TempDir(): test names make paths long enough to hit the ~108 byte
	// sockaddr_un limit.
	dir, err := os.MkdirTemp("", "sambox")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.Serve(ctx, l); err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return path
}

// startEcho returns the address of a server that echoes what it is sent.
func startEcho(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return l.Addr().String()
}

// dialRaw speaks the protocol by hand, for the cases a well-behaved client
// library will never produce.
func dialRaw(t *testing.T, path string) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	return conn
}

// greetNoAuth completes method selection and returns the connection ready for a
// request.
func greetNoAuth(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte{socks5Version, 1, methodNoAuth}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if reply[0] != socks5Version || reply[1] != methodNoAuth {
		t.Fatalf("method selection = %v, want [5 0]", reply)
	}
}

func readReplyCode(t *testing.T, conn net.Conn) byte {
	t.Helper()
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[0] != socks5Version {
		t.Fatalf("reply version = %d, want %d", reply[0], socks5Version)
	}
	return reply[1]
}

// TestConnectPreservesDestinationName is the property the whole boundary rests
// on: policy must see the name the agent asked for, never a resolved address.
func TestConnectPreservesDestinationName(t *testing.T) {
	echo := startEcho(t)

	seen := make(chan Destination, 1)
	path := startSOCKS5(t, &SOCKS5Server{
		Dialer: DialerFunc(func(ctx context.Context, creds *Credentials, dst Destination) (net.Conn, error) {
			seen <- dst
			return net.Dial("tcp", echo)
		}),
	})

	dialer, err := proxy.SOCKS5("unix", path, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("proxy.SOCKS5: %v", err)
	}
	conn, err := dialer.Dial("tcp", "api.github.com:443")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "ping" {
		t.Errorf("echo = %q, want %q", got, "ping")
	}

	dst := <-seen
	if !dst.IsName {
		t.Errorf("destination %+v was not reported as a name", dst)
	}
	if dst.Name != "api.github.com" || dst.Port != 443 {
		t.Errorf("destination = %s, want api.github.com:443", dst)
	}
}

func TestConnectDeniedByPolicy(t *testing.T) {
	path := startSOCKS5(t, &SOCKS5Server{
		Dialer: DialerFunc(func(ctx context.Context, creds *Credentials, dst Destination) (net.Conn, error) {
			return nil, ErrNotAllowed
		}),
	})

	conn := dialRaw(t, path)
	greetNoAuth(t, conn)
	writeConnectByName(t, conn, "evil.example", 80)

	if code := readReplyCode(t, conn); code != replyNotAllowed {
		t.Errorf("reply = %#x, want %#x (connection not allowed by ruleset)", code, replyNotAllowed)
	}
}

func TestUnsupportedCommandsAreRefused(t *testing.T) {
	path := startSOCKS5(t, &SOCKS5Server{
		Dialer: DialerFunc(func(ctx context.Context, creds *Credentials, dst Destination) (net.Conn, error) {
			t.Error("dialer must not be reached for an unsupported command")
			return nil, errors.New("unreachable")
		}),
	})

	// BIND and UDP ASSOCIATE. UDP is refused on purpose: the only way out of a
	// sandbox is a named TCP flow.
	for _, cmd := range []byte{0x02, 0x03} {
		conn := dialRaw(t, path)
		greetNoAuth(t, conn)
		if _, err := conn.Write([]byte{socks5Version, cmd, 0x00, atypIPv4, 127, 0, 0, 1, 0x00, 0x50}); err != nil {
			t.Fatalf("write request: %v", err)
		}
		if code := readReplyCode(t, conn); code != replyCommandNotSupported {
			t.Errorf("cmd %#x: reply = %#x, want %#x", cmd, code, replyCommandNotSupported)
		}
	}
}

func TestUnsupportedAddressTypeIsRefused(t *testing.T) {
	path := startSOCKS5(t, &SOCKS5Server{
		Dialer: DialerFunc(func(ctx context.Context, creds *Credentials, dst Destination) (net.Conn, error) {
			t.Error("dialer must not be reached for an unsupported address type")
			return nil, errors.New("unreachable")
		}),
	})

	conn := dialRaw(t, path)
	greetNoAuth(t, conn)
	if _, err := conn.Write([]byte{socks5Version, cmdConnect, 0x00, 0x02, 0x00, 0x50}); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if code := readReplyCode(t, conn); code != replyAddrTypeNotSupported {
		t.Errorf("reply = %#x, want %#x", code, replyAddrTypeNotSupported)
	}
}

func TestConnectByIPLiteralIsNotReportedAsAName(t *testing.T) {
	echo := startEcho(t)

	seen := make(chan Destination, 1)
	path := startSOCKS5(t, &SOCKS5Server{
		Dialer: DialerFunc(func(ctx context.Context, creds *Credentials, dst Destination) (net.Conn, error) {
			seen <- dst
			return net.Dial("tcp", echo)
		}),
	})

	conn := dialRaw(t, path)
	greetNoAuth(t, conn)
	if _, err := conn.Write([]byte{socks5Version, cmdConnect, 0x00, atypIPv4, 192, 0, 2, 10, 0x01, 0xBB}); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if code := readReplyCode(t, conn); code != replySuccess {
		t.Fatalf("reply = %#x, want success", code)
	}

	dst := <-seen
	if dst.IsName {
		t.Errorf("destination %+v was reported as a name", dst)
	}
	if dst.Name != "192.0.2.10" || dst.Port != 443 {
		t.Errorf("destination = %s, want 192.0.2.10:443", dst)
	}
}

// TestAuthenticationIsNotDowngraded pins that a server expecting credentials
// refuses an anonymous client instead of serving it unidentified.
func TestAuthenticationIsNotDowngraded(t *testing.T) {
	path := startSOCKS5(t, &SOCKS5Server{
		Dialer: DialerFunc(func(ctx context.Context, creds *Credentials, dst Destination) (net.Conn, error) {
			t.Error("dialer must not be reached for an unauthenticated client")
			return nil, errors.New("unreachable")
		}),
		Authenticate: func(Credentials) error { return nil },
	})

	conn := dialRaw(t, path)
	if _, err := conn.Write([]byte{socks5Version, 1, methodNoAuth}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if reply[1] != methodNoAcceptable {
		t.Errorf("method selection = %#x, want %#x (no acceptable methods)", reply[1], methodNoAcceptable)
	}
}

func TestAuthenticatedFlowCarriesCredentials(t *testing.T) {
	echo := startEcho(t)

	seen := make(chan *Credentials, 1)
	path := startSOCKS5(t, &SOCKS5Server{
		Dialer: DialerFunc(func(ctx context.Context, creds *Credentials, dst Destination) (net.Conn, error) {
			seen <- creds
			return net.Dial("tcp", echo)
		}),
		Authenticate: func(c Credentials) error {
			if c.Username != "reviewer-7.prod.acme.example" {
				return errors.New("unknown agent")
			}
			return nil
		},
	})

	auth := &proxy.Auth{User: "reviewer-7.prod.acme.example", Password: "admission-token"}
	dialer, err := proxy.SOCKS5("unix", path, auth, proxy.Direct)
	if err != nil {
		t.Fatalf("proxy.SOCKS5: %v", err)
	}
	conn, err := dialer.Dial("tcp", "code-reviewer.mcp.sam.alt:80")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	creds := <-seen
	if creds == nil {
		t.Fatal("dialer received no credentials")
	}
	if creds.Username != "reviewer-7.prod.acme.example" || creds.Password != "admission-token" {
		t.Errorf("credentials = %+v, want the agent id and its admission token", creds)
	}
}

func TestRejectedCredentialsFailTheHandshake(t *testing.T) {
	path := startSOCKS5(t, &SOCKS5Server{
		Dialer: DialerFunc(func(ctx context.Context, creds *Credentials, dst Destination) (net.Conn, error) {
			t.Error("dialer must not be reached when authentication fails")
			return nil, errors.New("unreachable")
		}),
		Authenticate: func(Credentials) error { return errors.New("unknown agent") },
	})

	dialer, err := proxy.SOCKS5("unix", path, &proxy.Auth{User: "bar", Password: "nope"}, proxy.Direct)
	if err != nil {
		t.Fatalf("proxy.SOCKS5: %v", err)
	}
	if _, err := dialer.Dial("tcp", "api.github.com:443"); err == nil {
		t.Fatal("Dial succeeded with rejected credentials, want an error")
	}
}

func TestNonSOCKS5GreetingIsDropped(t *testing.T) {
	path := startSOCKS5(t, &SOCKS5Server{
		Dialer: DialerFunc(func(ctx context.Context, creds *Credentials, dst Destination) (net.Conn, error) {
			t.Error("dialer must not be reached for a non-SOCKS5 client")
			return nil, errors.New("unreachable")
		}),
	})

	conn := dialRaw(t, path)
	if _, err := conn.Write([]byte{0x04, 0x01}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("read after bad version = %v, want EOF", err)
	}
}

// TestServeDropsFlowsOnCancel pins that shutdown is prompt. An established
// relay only ends when one side closes, so without this an idle keep-alive
// connection holds the gateway open until some unrelated timeout fires.
func TestServeDropsFlowsOnCancel(t *testing.T) {
	echo := startEcho(t)

	dir, err := os.MkdirTemp("", "sambox")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "agent.sock")

	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := &SOCKS5Server{
		Dialer: DialerFunc(func(ctx context.Context, creds *Credentials, dst Destination) (net.Conn, error) {
			return net.Dial("tcp", echo)
		}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, l) }()

	dialer, err := proxy.SOCKS5("unix", socket, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("proxy.SOCKS5: %v", err)
	}
	conn, err := dialer.Dial("tcp", "api.github.com:443")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// The flow is established and idle, which is the case that used to hang.
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after cancel; an idle flow is holding shutdown open")
	}
}

func TestReplyCodeFor(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want byte
	}{
		{"policy denial", ErrNotAllowed, replyNotAllowed},
		{"unreachable", ErrHostUnreachable, replyHostUnreachable},
		{"refused", ErrConnectionRefused, replyConnectionRefused},
		{"wrapped denial", errors.Join(errors.New("context"), ErrNotAllowed), replyNotAllowed},
		{"anything else stays generic", errors.New("boom"), replyGeneralFailure},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := replyCodeFor(tc.err); got != tc.want {
				t.Errorf("replyCodeFor(%v) = %#x, want %#x", tc.err, got, tc.want)
			}
		})
	}
}

func writeConnectByName(t *testing.T, conn net.Conn, name string, port uint16) {
	t.Helper()
	req := []byte{socks5Version, cmdConnect, 0x00, atypDomain, byte(len(name))}
	req = append(req, name...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
}
