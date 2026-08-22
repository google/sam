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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// SOCKS5 (RFC 1928) is the sandbox boundary protocol. It is chosen over HTTP
// proxying for one property above all: a request carries the destination
// *name*, so egress policy is decided on "api.github.com" rather than on an
// address that says nothing about who is being talked to. It is also
// protocol-agnostic, and its reply codes give a policy denial a first-class
// representation that the guest kernel turns into a clean connection refusal.
//
// Only CONNECT is implemented. BIND is meaningless here, and UDP ASSOCIATE is
// refused deliberately: leaving it out means the only way out of a sandbox is a
// named TCP flow, which is also the only shape the policy engine can reason
// about. Inbound traffic reaches an agent over its own reverse channel, not
// over BIND.

const (
	socks5Version   = 0x05
	userAuthVersion = 0x01

	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// SOCKS5 reply codes (RFC 1928 section 6).
const (
	replySuccess              = 0x00
	replyGeneralFailure       = 0x01
	replyNotAllowed           = 0x02
	replyHostUnreachable      = 0x04
	replyConnectionRefused    = 0x05
	replyCommandNotSupported  = 0x07
	replyAddrTypeNotSupported = 0x08
)

// handshakeTimeout bounds the negotiation only. Once a flow is established it
// may stream for as long as it likes, so no deadline survives into the proxy.
const handshakeTimeout = 10 * time.Second

// Errors a Dialer returns to select a SOCKS5 reply code. Anything else becomes
// a general failure, which is the right default: an unrecognised failure must
// not be reported to a sandbox as a precise diagnostic.
var (
	// ErrNotAllowed is a policy denial: the destination is not permitted.
	ErrNotAllowed = errors.New("connection not allowed by ruleset")

	// ErrHostUnreachable means the destination could not be resolved or routed.
	ErrHostUnreachable = errors.New("host unreachable")

	// ErrConnectionRefused means the destination actively refused the flow.
	ErrConnectionRefused = errors.New("connection refused")
)

// Destination is a requested target exactly as it arrived on the sandbox
// boundary. Name is a domain when the client sent one, which is the case for
// every flow that came through tun2socks with virtual DNS; a literal address
// arrives when the sandbox dialled an IP directly, and IsName says which.
type Destination struct {
	Name   string
	Port   uint16
	IsName bool
}

// Address renders the destination as a dial target.
func (d Destination) Address() string {
	return net.JoinHostPort(d.Name, strconv.Itoa(int(d.Port)))
}

func (d Destination) String() string { return d.Address() }

// Credentials are the RFC 1929 username and password. When one sam-box
// multiplexes several agents over a single socket, this is how a flow says
// which agent it belongs to; the password is never logged.
type Credentials struct {
	Username string
	Password string
}

// Dialer decides whether a requested destination may be reached and opens it.
// It is the single policy enforcement point on the sandbox boundary.
type Dialer interface {
	DialDestination(ctx context.Context, creds *Credentials, dst Destination) (net.Conn, error)
}

// DialerFunc adapts a function to Dialer.
type DialerFunc func(ctx context.Context, creds *Credentials, dst Destination) (net.Conn, error)

func (f DialerFunc) DialDestination(ctx context.Context, creds *Credentials, dst Destination) (net.Conn, error) {
	return f(ctx, creds, dst)
}

// SOCKS5Server serves the sandbox-facing side of the boundary.
type SOCKS5Server struct {
	// Dialer is required.
	Dialer Dialer

	// Authenticate, when set, makes RFC 1929 username/password the only
	// acceptable method: a client that offers no credentials is rejected rather
	// than silently downgraded to an anonymous flow.
	Authenticate func(Credentials) error
}

// Serve accepts connections until the listener fails or ctx is cancelled.
func (s *SOCKS5Server) Serve(ctx context.Context, l net.Listener) error {
	if s.Dialer == nil {
		return errors.New("sambox: SOCKS5Server requires a Dialer")
	}

	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Cancelling must drop flows, not wait them out: an established
			// relay only ends when one side closes, so an idle keep-alive
			// connection would otherwise hold shutdown open until some other
			// timeout fires.
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stop()
			s.handle(ctx, conn)
		}()
	}
}

func (s *SOCKS5Server) handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return
	}

	creds, err := s.negotiate(conn)
	if err != nil {
		return
	}

	dst, err := readRequest(conn)
	if err != nil {
		var rerr *replyError
		if errors.As(err, &rerr) {
			_ = writeReply(conn, rerr.code)
		}
		return
	}

	// Negotiation is over. Dialling a mesh destination can involve discovery, so
	// it must not inherit the handshake deadline; bounding it is the Dialer's
	// job, through the context it is given.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}

	upstream, err := s.Dialer.DialDestination(ctx, creds, dst)
	if err != nil {
		_ = writeReply(conn, replyCodeFor(err))
		return
	}
	defer func() { _ = upstream.Close() }()

	if err := writeReply(conn, replySuccess); err != nil {
		return
	}

	relay(conn, upstream)
}

// negotiate performs method selection and, when required, RFC 1929 auth.
func (s *SOCKS5Server) negotiate(conn net.Conn) (*Credentials, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != socks5Version {
		return nil, fmt.Errorf("unsupported SOCKS version %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, err
	}

	want := byte(methodNoAuth)
	if s.Authenticate != nil {
		want = methodUserPass
	}
	if !containsByte(methods, want) {
		_, _ = conn.Write([]byte{socks5Version, methodNoAcceptable})
		return nil, fmt.Errorf("client offered no acceptable authentication method")
	}
	if _, err := conn.Write([]byte{socks5Version, want}); err != nil {
		return nil, err
	}
	if s.Authenticate == nil {
		return nil, nil
	}

	creds, err := readUserPass(conn)
	if err != nil {
		return nil, err
	}
	if err := s.Authenticate(*creds); err != nil {
		_, _ = conn.Write([]byte{userAuthVersion, 0x01})
		log.Printf("sambox: SOCKS5 authentication rejected for user %q", creds.Username)
		return nil, err
	}
	if _, err := conn.Write([]byte{userAuthVersion, 0x00}); err != nil {
		return nil, err
	}
	return creds, nil
}

func readUserPass(conn net.Conn) (*Credentials, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != userAuthVersion {
		return nil, fmt.Errorf("unsupported username/password auth version %d", header[0])
	}

	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return nil, err
	}

	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return nil, err
	}
	password := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return nil, err
	}

	return &Credentials{Username: string(username), Password: string(password)}, nil
}

// replyError carries the SOCKS5 code a malformed or unsupported request must be
// answered with.
type replyError struct {
	code byte
	err  error
}

func (e *replyError) Error() string { return e.err.Error() }

func readRequest(conn net.Conn) (Destination, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return Destination{}, err
	}
	if header[0] != socks5Version {
		return Destination{}, fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	if header[1] != cmdConnect {
		return Destination{}, &replyError{replyCommandNotSupported, fmt.Errorf("unsupported command %d", header[1])}
	}

	var dst Destination
	switch header[3] {
	case atypDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return Destination{}, err
		}
		if length[0] == 0 {
			return Destination{}, &replyError{replyGeneralFailure, errors.New("empty domain name")}
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return Destination{}, err
		}
		dst.Name = string(name)
		dst.IsName = true
	case atypIPv4, atypIPv6:
		size := net.IPv4len
		if header[3] == atypIPv6 {
			size = net.IPv6len
		}
		addr := make([]byte, size)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return Destination{}, err
		}
		dst.Name = net.IP(addr).String()
	default:
		return Destination{}, &replyError{replyAddrTypeNotSupported, fmt.Errorf("unsupported address type %d", header[3])}
	}

	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return Destination{}, err
	}
	dst.Port = binary.BigEndian.Uint16(port)

	return dst, nil
}

// writeReply answers with a bound address of 0.0.0.0:0: the client has no use
// for the real one, and it would leak the host's addressing into the sandbox.
func writeReply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{socks5Version, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func replyCodeFor(err error) byte {
	switch {
	case errors.Is(err, ErrNotAllowed):
		return replyNotAllowed
	case errors.Is(err, ErrHostUnreachable):
		return replyHostUnreachable
	case errors.Is(err, ErrConnectionRefused):
		return replyConnectionRefused
	default:
		return replyGeneralFailure
	}
}

func relay(client, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, client)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
	}()
	wg.Wait()
}

// closeWrite propagates a half-close so a peer waiting on EOF is not left
// hanging until a timeout.
func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
}

func containsByte(haystack []byte, needle byte) bool {
	for _, b := range haystack {
		if b == needle {
			return true
		}
	}
	return false
}
