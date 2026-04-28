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
	"io"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)


type mockStream struct {
	r        io.Reader
	w        io.Writer
	protocol protocol.ID
}

func (s *mockStream) Read(p []byte) (n int, err error) {
	return s.r.Read(p)
}
func (s *mockStream) Write(p []byte) (n int, err error) {
	return s.w.Write(p)
}
func (s *mockStream) Close() error {
	if c, ok := s.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
func (s *mockStream) Protocol() protocol.ID {
	return s.protocol
}

type mockConn struct {
	network.Conn // Embed interface
	remotePeer peer.ID
}

func (c *mockConn) RemotePeer() peer.ID {
	return c.remotePeer
}

func (s *mockStream) Conn() network.Conn {
	return &mockConn{remotePeer: peer.ID("dummy-peer-id")}
}
func (s *mockStream) Reset() error {
	return nil
}
func (s *mockStream) CloseRead() error {
	return nil
}
func (s *mockStream) CloseWrite() error {
	return nil
}
func (s *mockStream) ID() string {
	return "dummy-stream-id"
}
func (s *mockStream) ResetWithError(code network.StreamErrorCode) error {
	return nil
}
func (s *mockStream) Scope() network.StreamScope {
	return nil
}
func (s *mockStream) SetDeadline(t time.Time) error {
	return nil
}
func (s *mockStream) SetReadDeadline(t time.Time) error {
	return nil
}
func (s *mockStream) SetWriteDeadline(t time.Time) error {
	return nil
}
func (s *mockStream) SetProtocol(id protocol.ID) error {
	s.protocol = id
	return nil
}
func (s *mockStream) Stat() network.Stats {
	return network.Stats{}
}

func TestZeroTrustMCPServer(t *testing.T) {
	pr1, pw1 := io.Pipe()
	pr2, pw2 := io.Pipe()

	serverStream := &mockStream{r: pr1, w: pw2, protocol: protocol.ID("/sam/mcp/1.0.0")}
	clientStream := &mockStream{r: pr2, w: pw1, protocol: protocol.ID("/sam/mcp/1.0.0")}

	node := &SamNode{}

	go func() {
		handler := node.WithBiscuitAuth(node.HandleMCPStream)
		handler(serverStream)
	}()

	// Test: Skip sending AuthFrame and write MCP message directly!
	if _, err := pw1.Write([]byte(`{"jsonrpc":"2.0","method":"initialize"}`)); err != nil {
		t.Fatalf("failed to write to pipe: %v", err)
	}
	if err := pw1.Close(); err != nil {
		t.Fatalf("failed to close pipe: %v", err)
	}

	// Server should read invalid auth frame and close stream!
	msg := make([]byte, 100)
	_, err := clientStream.Read(msg)
	if err == nil {
		t.Errorf("Expected error reading from stream (stream should be closed by server), got nil")
	}
}
