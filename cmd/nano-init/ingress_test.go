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

package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestIngressSocketIsOwnerOnly pins the permissions on the one hole punched
// through the sandbox boundary. The ingress socket relays "CONNECT <port>" to
// any port inside the namespace with no token and no capability of its own, so
// its mode is the only thing standing between a neighbouring process and the
// agent. Both sibling sockets in this repo are 0600 for the same reason; the
// umask that would otherwise decide this is not ours to assume.
func TestIngressSocketIsOwnerOnly(t *testing.T) {
	// Loosen the umask so a missing chmod really would leave the socket group-
	// and world-accessible, rather than being masked into passing.
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	socketPath := filepath.Join(t.TempDir(), "ingress.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	served := make(chan error, 1)
	go func() { served <- serveIngress(ctx, socketPath) }()

	deadline := time.Now().Add(2 * time.Second)
	var info os.FileInfo
	for {
		var err error
		if info, err = os.Stat(socketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ingress socket %s never appeared: %v", socketPath, err)
		}
		time.Sleep(5 * time.Millisecond)
	}

	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("ingress socket permissions are %#o, want 0600", perm)
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("serveIngress returned %v, want nil on cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("serveIngress did not return after cancellation")
	}
}

// floodConn is a client that opens the ingress socket and then never sends the
// newline the handshake ends with. It counts what the handler reads, so a test
// can hold the handler to the bound the package documents.
type floodConn struct {
	read  int
	limit int
	reply bytes.Buffer
}

func (c *floodConn) Read(p []byte) (int, error) {
	if c.read >= c.limit {
		return 0, io.EOF
	}
	n := len(p)
	if remaining := c.limit - c.read; n > remaining {
		n = remaining
	}
	for i := range p[:n] {
		p[i] = 'A'
	}
	c.read += n
	return n, nil
}

func (c *floodConn) Write(p []byte) (int, error)      { return c.reply.Write(p) }
func (c *floodConn) Close() error                     { return nil }
func (c *floodConn) LocalAddr() net.Addr              { return floodAddr{} }
func (c *floodConn) RemoteAddr() net.Addr             { return floodAddr{} }
func (c *floodConn) SetDeadline(time.Time) error      { return nil }
func (c *floodConn) SetReadDeadline(time.Time) error  { return nil }
func (c *floodConn) SetWriteDeadline(time.Time) error { return nil }

type floodAddr struct{}

func (floodAddr) Network() string { return "flood" }
func (floodAddr) String() string  { return "flood" }

// TestHandleIngressBoundsTheHandshake holds the handshake read to the size the
// package names. ingressMaxHandshake sizes a bufio.Reader, and that bounds only
// what one fill holds: ReadString goes on growing a buffer of its own until it
// finds a newline, so a client that sends none could make this process -- PID 1
// in the sandbox -- accumulate for as long as the read deadline allows.
func TestHandleIngressBoundsTheHandshake(t *testing.T) {
	const flood = 1 << 20
	conn := &floodConn{limit: flood}

	err := handleIngress(context.Background(), conn)
	if err == nil {
		t.Fatal("handleIngress accepted a handshake with no newline, want an error")
	}
	if got := conn.read; got > ingressMaxHandshake {
		t.Errorf("handleIngress read %d bytes of a %d byte flood, want at most %d", got, flood, ingressMaxHandshake)
	}
	if answer := conn.reply.String(); !strings.HasPrefix(answer, "ERR ") {
		t.Errorf("handleIngress answered %q, want an ERR line: a gateway that gets nothing back cannot tell a refusal from a sandbox that never started", answer)
	}
}

// TestHandleIngressRelaysPipelinedBytes covers what a bounded read must not
// break. The gateway may send its first request bytes in the same write as the
// handshake, and those are in the reader rather than the socket by the time the
// agent is dialled, so they are forwarded by hand.
func TestHandleIngressRelaysPipelinedBytes(t *testing.T) {
	const pipelined = "HELLO"

	agent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen as the agent: %v", err)
	}
	defer func() { _ = agent.Close() }()
	_, port, err := net.SplitHostPort(agent.Addr().String())
	if err != nil {
		t.Fatalf("split the agent address: %v", err)
	}

	delivered := make(chan string, 1)
	go func() {
		c, err := agent.Accept()
		if err != nil {
			delivered <- "accept: " + err.Error()
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, len(pipelined))
		if _, err := io.ReadFull(c, buf); err != nil {
			delivered <- "read: " + err.Error()
			return
		}
		delivered <- string(buf)
	}()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	done := make(chan error, 1)
	go func() { done <- handleIngress(context.Background(), server) }()
	go func() { _, _ = io.WriteString(client, "CONNECT "+port+"\n"+pipelined) }()

	reply, err := bufio.NewReader(io.LimitReader(client, 128)).ReadString('\n')
	if err != nil {
		t.Fatalf("read the handshake answer: %v", err)
	}
	if got := strings.TrimSpace(reply); got != "OK" {
		t.Fatalf("the handshake answer is %q, want OK", got)
	}

	select {
	case got := <-delivered:
		if got != pipelined {
			t.Errorf("the agent received %q, want %q", got, pipelined)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the agent never received the bytes pipelined behind the handshake")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("handleIngress did not return once both ends were done")
	}
}

// TestParseIngressConnect pins the one line the gateway sends first. Everything
// past it is relayed verbatim, so this is where a malformed request has to stop.
func TestParseIngressConnect(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want int
	}{
		{name: "port", line: "CONNECT 8080\n", want: 8080},
		{name: "lowercase verb", line: "connect 8080\n", want: 8080},
		{name: "extra spaces", line: "  CONNECT   8080  \n", want: 8080},
		{name: "lowest port", line: "CONNECT 1\n", want: 1},
		{name: "highest port", line: "CONNECT 65535\n", want: 65535},
		{name: "port zero", line: "CONNECT 0\n"},
		{name: "above the port range", line: "CONNECT 65536\n"},
		{name: "negative", line: "CONNECT -1\n"},
		{name: "not a number", line: "CONNECT http\n"},
		{name: "wrong verb", line: "GET 8080\n"},
		{name: "no port", line: "CONNECT\n"},
		{name: "trailing junk", line: "CONNECT 8080 now\n"},
		{name: "empty", line: "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseIngressConnect(tc.line)
			if tc.want == 0 {
				if err == nil {
					t.Fatalf("parseIngressConnect(%q) = %d, want an error", tc.line, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseIngressConnect(%q) returned %v, want %d", tc.line, err, tc.want)
			}
			if got != tc.want {
				t.Errorf("parseIngressConnect(%q) = %d, want %d", tc.line, got, tc.want)
			}
		})
	}
}
