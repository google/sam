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
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// An agent that serves the mesh needs traffic delivered to it, and delivery is
// the direction the sandbox is built to prevent. The gateway cannot dial the
// agent: a sandbox has a network namespace of its own, so the gateway's
// 127.0.0.1 is its own loopback and not the agent's. That is true of every
// profile -- a microVM, a container with no network, and a pod where nano-init
// made the namespace itself -- because it is a consequence of the isolation
// rather than of any one runtime.
//
// The way out is the way in. Egress already crosses the boundary over a
// pathname Unix socket, which network namespaces do not apply to because it is
// a filesystem object. So the reverse channel is another one, listened on by
// this process, which is inside the namespace and can therefore reach the
// agent at the address the gateway meant.
//
// The handshake is Firecracker's, deliberately: connect, send "CONNECT <port>",
// read "OK". A microVM can offer the identical protocol over vsock without the
// gateway learning the difference.

const (
	ingressConnectTimeout = 10 * time.Second
	// A port is at most five digits and a line at most one, so anything longer
	// is a client that has misunderstood.
	ingressMaxHandshake = 64
)

// serveIngress accepts the gateway's inbound connections and joins each one to
// the port the agent serves.
func serveIngress(ctx context.Context, socketPath string) error {
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on the ingress socket %s: %w", socketPath, err)
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	log.Printf("serving ingress on %s", socketPath)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept on the ingress socket: %w", err)
		}
		go func() {
			if err := handleIngress(ctx, conn); err != nil {
				log.Printf("ingress connection: %v", err)
			}
		}()
	}
}

// handleIngress reads which port the gateway is asking for and connects it.
func handleIngress(ctx context.Context, conn net.Conn) error {
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(ingressConnectTimeout))
	reader := bufio.NewReaderSize(conn, ingressMaxHandshake)
	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read the ingress handshake: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	port, err := parseIngressConnect(line)
	if err != nil {
		// Answered rather than dropped: a gateway that gets nothing back
		// cannot tell a refusal from a sandbox that never started.
		_, _ = io.WriteString(conn, "ERR "+err.Error()+"\n")
		return err
	}

	// The agent is in this namespace, which is the whole reason this hop
	// exists: here 127.0.0.1 means what the gateway intended.
	dialer := net.Dialer{Timeout: ingressConnectTimeout}
	agent, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		_, _ = io.WriteString(conn, "ERR the agent is not listening\n")
		return fmt.Errorf("dial the agent on port %d: %w", port, err)
	}
	defer func() { _ = agent.Close() }()

	if _, err := io.WriteString(conn, "OK\n"); err != nil {
		return fmt.Errorf("acknowledge the ingress handshake: %w", err)
	}

	// Anything the gateway sent after the handshake is already buffered.
	if n := reader.Buffered(); n > 0 {
		pending, err := reader.Peek(n)
		if err != nil {
			return fmt.Errorf("recover buffered request bytes: %w", err)
		}
		if _, err := agent.Write(pending); err != nil {
			return fmt.Errorf("forward buffered request bytes: %w", err)
		}
	}

	relay(conn, agent)
	return nil
}

// parseIngressConnect reads the one line the gateway sends first.
func parseIngressConnect(line string) (int, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "CONNECT") {
		return 0, fmt.Errorf("expected \"CONNECT <port>\"")
	}
	port, err := strconv.Atoi(fields[1])
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%q is not a port", fields[1])
	}
	return port, nil
}

// relay joins two connections until either end is done with the other.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		closeWrite(a)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		closeWrite(b)
	}()
	wg.Wait()
}

// closeWrite ends one direction so the far side sees EOF, falling back to a
// full close for connections that cannot half-close.
func closeWrite(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
