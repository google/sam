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

package node

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/google/sam/api"
	lru "github.com/hashicorp/golang-lru/v2"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

type mockConn struct {
	remotePeer peer.ID
}

func (c *mockConn) RemotePeer() peer.ID                               { return c.remotePeer }
func (c *mockConn) LocalPeer() peer.ID                                { return "" }
func (c *mockConn) LocalMultiaddr() multiaddr.Multiaddr               { return nil }
func (c *mockConn) RemoteMultiaddr() multiaddr.Multiaddr              { return nil }
func (c *mockConn) Stat() network.ConnStats                           { return network.ConnStats{} }
func (c *mockConn) Scope() network.ConnScope                          { return nil }
func (c *mockConn) Close() error                                      { return nil }
func (c *mockConn) CloseWithError(network.ConnErrorCode) error        { return nil }
func (c *mockConn) ConnState() network.ConnectionState                { return network.ConnectionState{} }
func (c *mockConn) GetStreams() []network.Stream                      { return nil }
func (c *mockConn) ID() string                                        { return "" }
func (c *mockConn) IsClosed() bool                                    { return false }
func (c *mockConn) NewStream(context.Context) (network.Stream, error) { return nil, nil }
func (c *mockConn) RemotePublicKey() crypto.PubKey                    { return nil }
func (c *mockConn) As(interface{}) bool                               { return false }

type mockStream struct {
	r        io.Reader
	w        io.Writer
	protocol protocol.ID
	conn     network.Conn
}

func (s *mockStream) Read(p []byte) (n int, err error)             { return s.r.Read(p) }
func (s *mockStream) Write(p []byte) (n int, err error)            { return s.w.Write(p) }
func (s *mockStream) Close() error                                 { return nil }
func (s *mockStream) Protocol() protocol.ID                        { return s.protocol }
func (s *mockStream) ID() string                                   { return "" }
func (s *mockStream) SetProtocol(protocol.ID) error                { return nil }
func (s *mockStream) CloseRead() error                             { return nil }
func (s *mockStream) CloseWrite() error                            { return nil }
func (s *mockStream) Reset() error                                 { return nil }
func (s *mockStream) ResetWithError(network.StreamErrorCode) error { return nil }
func (s *mockStream) SetDeadline(time.Time) error                  { return nil }
func (s *mockStream) SetReadDeadline(time.Time) error              { return nil }
func (s *mockStream) SetWriteDeadline(time.Time) error             { return nil }
func (s *mockStream) Stat() network.Stats                          { return network.Stats{} }
func (s *mockStream) Conn() network.Conn                           { return s.conn }
func (s *mockStream) Scope() network.StreamScope                   { return nil }

func TestAuthorize(t *testing.T) {
	dir, err := os.MkdirTemp("", "middleware-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(dir)
	}()

	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = store.Close()
	}()
	golog.SetAllLoggers(golog.LevelDebug)

	// Create a biscuit token
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	builder := biscuit.NewBuilder(priv)
	_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: "target_unrestricted"}})
	dummyPeer := peer.ID("dummy-peer")

	// Bind to peer
	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
	}})
	if err != nil {
		t.Fatal(err)
	}

	// Add client_peer_id for replay check
	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "client_peer_id",
		IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
	}})
	if err != nil {
		t.Fatal(err)
	}

	// Add fact to match baseline rule
	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactGrantedServiceExact,
		IDs:  []biscuit.Term{biscuit.String(api.SystemNamespace), biscuit.String("/test/proto")},
	}})
	if err != nil {
		t.Fatal(err)
	}

	b, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	tokenBytes, err := b.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	node := &SamNode{
		Store:          store,
		trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	req := RequestContext{
		PeerID:   dummyPeer,
		Protocol: "/test/proto",
	}

	if err := node.Authorize(tokenBytes, req, pub); err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
}

func TestBaselineRules(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	dummyPeer := peer.ID("dummy-peer")

	tests := []struct {
		name          string
		mintToken     func(t *testing.T, builder biscuit.Builder)
		protocol      string
		target        string
		expectSuccess bool
	}{
		{
			name: "Baseline Rule 1: Exact Match",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				factStr := fmt.Sprintf(`%s("mcp", "test_tool")`, api.FactGrantedServiceExact)
				fact, _ := parser.FromStringFact(factStr)
				_ = builder.AddAuthorityFact(fact)
			},
			protocol:      "test_tool",
			target:        "mcp://test_tool",
			expectSuccess: true,
		},
		{
			name: "Baseline Rule 2: Global Wildcard",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				factStr := fmt.Sprintf(`%s()`, api.FactGrantedServiceAllTypes)
				fact, _ := parser.FromStringFact(factStr)
				_ = builder.AddAuthorityFact(fact)
			},
			protocol:      "anything",
			target:        "mcp://anything",
			expectSuccess: true,
		},

		{
			name: "Baseline Rule 4: Type Wildcard",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				factStr := fmt.Sprintf(`%s("mcp")`, api.FactGrantedServiceAll)
				fact, _ := parser.FromStringFact(factStr)
				_ = builder.AddAuthorityFact(fact)
			},
			protocol:      "test_tool",
			target:        "mcp://test_tool",
			expectSuccess: true,
		},
		{
			name: "Baseline Rule Rejection: Type Wildcard does not allow other types",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				factStr := fmt.Sprintf(`%s("mcp")`, api.FactGrantedServiceAll)
				fact, _ := parser.FromStringFact(factStr)
				_ = builder.AddAuthorityFact(fact)
			},
			protocol:      "test_tool",
			target:        "system://test_tool",
			expectSuccess: false,
		},
		{
			name: "Baseline Replay Check Rejection: mismatched peer ID",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				factStr := fmt.Sprintf(`%s("mcp", "test_tool")`, api.FactGrantedServiceExact)
				fact, _ := parser.FromStringFact(factStr)
				_ = builder.AddAuthorityFact(fact)
				// deliberately add a different client_peer_id than the connection peer ID
				err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: api.FactClientPeerID,
					IDs:  []biscuit.Term{biscuit.String("different-peer")},
				}})
			},
			protocol:      "test_tool",
			target:        "mcp://test_tool",
			expectSuccess: false, // Should fail the connection_peer_id check
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: "target_unrestricted"}})
			_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: "node",
				IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
			}})

			// For the happy paths, add the matching client_peer_id
			if tt.name != "Baseline Replay Check Rejection: mismatched peer ID" {
				_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: "client_peer_id",
					IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
				}})
			}

			tt.mintToken(t, builder)

			b, _ := builder.Build()
			tokenBytes, _ := b.Serialize()

			node := &SamNode{
				trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
				BiscuitTimeout: 500 * time.Millisecond,
			}

			req := RequestContext{
				PeerID:   dummyPeer,
				Protocol: tt.protocol,
				Target:   tt.target,
			}

			err = node.Authorize(tokenBytes, req, pub)
			if tt.expectSuccess && err != nil {
				t.Errorf("expected success, got error: %v", err)
			} else if !tt.expectSuccess && err == nil {
				t.Error("expected failure, got success")
			}
		})
	}
}

func TestEnterprisePolicyEngine(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	dummyPeer := peer.ID("dummy-peer")

	tests := []struct {
		name            string
		mintToken       func(t *testing.T, builder biscuit.Builder)
		operation       string
		localPolicyYAML string
		expectSuccess   bool
	}{
		{
			name: "Case 1 (Happy Path)",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				fact, err := parser.FromStringFact(fmt.Sprintf(`%s(%q, "query_db")`, api.FactGrantedServiceExact, api.SystemNamespace))
				if err != nil {
					t.Fatal(err)
				}
				if err := builder.AddAuthorityFact(fact); err != nil {
					t.Fatal(err)
				}
			},
			operation:     "query_db",
			expectSuccess: true,
		},
		{
			name: "Case 2 (Unauthorized Tool)",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				fact, err := parser.FromStringFact(fmt.Sprintf(`%s(%q, "query_db")`, api.FactGrantedServiceExact, api.SystemNamespace))
				if err != nil {
					t.Fatal(err)
				}
				if err := builder.AddAuthorityFact(fact); err != nil {
					t.Fatal(err)
				}
			},
			operation:     "reboot_server",
			expectSuccess: false,
		},
		{
			name: "Case 3 (Wildcard Access)",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				fact, err := parser.FromStringFact(fmt.Sprintf(`%s()`, api.FactGrantedServiceAllTypes))
				if err != nil {
					t.Fatal(err)
				}
				if err := builder.AddAuthorityFact(fact); err != nil {
					t.Fatal(err)
				}
			},
			operation:     "anything",
			expectSuccess: true,
		},
		{
			name: "Case 4 (Local Attenuation Override)",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				fact1, err := parser.FromStringFact(fmt.Sprintf(`%s()`, api.FactGrantedServiceAllTypes))
				if err != nil {
					t.Fatal(err)
				}
				if err := builder.AddAuthorityFact(fact1); err != nil {
					t.Fatal(err)
				}
				fact2, err := parser.FromStringFact(`user("alice")`)
				if err != nil {
					t.Fatal(err)
				}
				if err := builder.AddAuthorityFact(fact2); err != nil {
					t.Fatal(err)
				}
			},
			operation: "query_db",
			localPolicyYAML: `
version: "v1alpha1"
attenuation:
  policies:
    - 'deny if user("alice");'
`,
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: api.FactTargetUnrestricted}})

			err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactNode,
				IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
			}})
			if err != nil {
				t.Fatal(err)
			}

			// Add client_peer_id for replay check
			err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactClientPeerID,
				IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
			}})
			if err != nil {
				t.Fatal(err)
			}

			tt.mintToken(t, builder)

			b, err := builder.Build()
			if err != nil {
				t.Fatal(err)
			}

			tokenBytes, err := b.Serialize()
			if err != nil {
				t.Fatal(err)
			}

			var localPolicy *NodeConfigComplete
			if tt.localPolicyYAML != "" {
				dir := t.TempDir()
				policyFile := filepath.Join(dir, "local_policy.yaml")
				if err := os.WriteFile(policyFile, []byte(tt.localPolicyYAML), 0644); err != nil {
					t.Fatal(err)
				}
				var err error
				localPolicy, err = LoadNodeConfig(policyFile)
				if err != nil {
					t.Fatalf("failed to load local policy: %v", err)
				}
			}

			node := &SamNode{
				trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
				LocalPolicy:    localPolicy,
				BiscuitTimeout: 500 * time.Millisecond,
			}

			req := RequestContext{
				PeerID:   dummyPeer,
				Protocol: string(tt.operation),
			}

			err = node.Authorize(tokenBytes, req, pub)
			if tt.expectSuccess {
				if err != nil {
					t.Errorf("expected success, got error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("expected failure, got success")
				}
			}
		})
	}
}

func TestRevocation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	dummyPeer := peer.ID("dummy-peer-id") // Must match mockStream.Conn().RemotePeer()

	builder := biscuit.NewBuilder(priv)
	_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: "target_unrestricted"}})
	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
	}})
	if err != nil {
		t.Fatal(err)
	}
	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "client_peer_id",
		IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
	}})
	if err != nil {
		t.Fatal(err)
	}

	b, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	tokenBytes, err := b.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	cache, _ := lru.New[string, int64](10000)
	rl, _ := NewPeerRateLimiter(100)
	node := &SamNode{
		trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
		revokedPeers:   cache,
		rateLimiter:    rl,
		BiscuitTimeout: 500 * time.Millisecond,
	}

	// Mark as revoked
	node.revokedPeers.Add(dummyPeer.String(), time.Now().Unix())

	pr1, pw1 := io.Pipe()
	pr2, pw2 := io.Pipe()

	serverStream := &mockStream{r: pr1, w: pw2, protocol: protocol.ID("/test/proto"), conn: &mockConn{remotePeer: dummyPeer}}

	// Run handler in goroutine
	go func() {
		handler := node.WithBiscuitAuth(func(s network.Stream, reqCtx RequestContext) {
			t.Error("Handler should not be called for revoked peer")
		})
		handler(serverStream)
	}()

	// Send AuthFrame
	writer := msgio.NewVarintWriter(pw1)
	authFrame := &api.AuthFrame{Biscuit: tokenBytes}
	data, _ := proto.Marshal(authFrame)
	if err := writer.WriteMsg(data); err != nil {
		t.Fatal(err)
	}

	// Read response
	reader := msgio.NewVarintReaderSize(pr2, 1024*64)
	msg, err := reader.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	var resp api.AuthResponse
	if err := proto.Unmarshal(msg, &resp); err != nil {
		t.Fatal(err)
	}

	if resp.Success {
		t.Error("expected failure for revoked peer, got success")
	}
	if resp.Error != "peer is revoked" {
		t.Errorf("expected error 'peer is revoked', got %q", resp.Error)
	}
}

func TestVerifyEvent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	node := &SamNode{
		trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	event := &api.MeshEvent{
		Type:      api.MeshEvent_BANNED,
		PeerId:    "attacker-peer",
		Timestamp: time.Now().UnixMilli(),
	}

	// Sign it
	event.Signature = nil
	data, err := proto.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	event.Signature = ed25519.Sign(priv, data)

	// Case 1: Valid signature
	if !node.verifyEvent(event) {
		t.Error("Expected event to be verified, got false")
	}

	// Case 2: Invalid signature
	event.Signature = []byte("invalid-sig")
	if node.verifyEvent(event) {
		t.Error("Expected event verification to fail, got true")
	}

	// Case 3: Missing signature
	event.Signature = nil
	if node.verifyEvent(event) {
		t.Error("Expected event verification to fail for missing signature, got true")
	}
}

func TestMiddlewareTargetChecks(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	dummyPeer := peer.ID("dummy-peer")

	tests := []struct {
		name          string
		mintToken     func(t *testing.T, builder biscuit.Builder)
		req           RequestContext
		expectSuccess bool
	}{
		{
			name: "Target Check: Allowed by User Fact",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: api.FactGrantedTargetExact,
					IDs:  []biscuit.Term{biscuit.String("user"), biscuit.String("bob")},
				}})
			},
			req: RequestContext{
				PeerID:   dummyPeer,
				Protocol: "test_tool",
				Target:   "mcp://test_tool",
				User:     "bob",
			},
			expectSuccess: true,
		},
		{
			name: "Target Check: Rejected by wrong User Fact",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: api.FactGrantedTargetExact,
					IDs:  []biscuit.Term{biscuit.String("user"), biscuit.String("alice")},
				}})
			},
			req: RequestContext{
				PeerID:   dummyPeer,
				Protocol: "test_tool",
				Target:   "mcp://test_tool",
				User:     "bob",
			},
			expectSuccess: false,
		},
		{
			name: "Target Check: Allowed by Group Fact",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: api.FactGrantedTargetExact,
					IDs:  []biscuit.Term{biscuit.String("group"), biscuit.String("eng")},
				}})
			},
			req: RequestContext{
				PeerID:   dummyPeer,
				Protocol: "test_tool",
				Target:   "mcp://test_tool",
				Group:    "eng",
			},
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			// Required basic facts
			_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactClientPeerID,
				IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
			}})
			_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactNode,
				IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
			}})
			// Allow exact service
			factStr := fmt.Sprintf(`%s("mcp", "test_tool")`, api.FactGrantedServiceExact)
			fact, _ := parser.FromStringFact(factStr)
			_ = builder.AddAuthorityFact(fact)

			tt.mintToken(t, builder)

			b, _ := builder.Build()
			tokenBytes, _ := b.Serialize()

			// Build the Node Identity Token
			idBuilder := biscuit.NewBuilder(priv)
			if tt.req.User != "" {
				_ = idBuilder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: "user",
					IDs:  []biscuit.Term{biscuit.String(tt.req.User)},
				}})
			}
			if tt.req.Group != "" {
				_ = idBuilder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: "group",
					IDs:  []biscuit.Term{biscuit.String(tt.req.Group)},
				}})
			}
			idB, _ := idBuilder.Build()
			idTokenBytes, _ := idB.Serialize()

			node := &SamNode{
				trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
				BiscuitTimeout: 500 * time.Millisecond,
			}
			node.SetIdentityCache(idTokenBytes)

			err = node.Authorize(tokenBytes, tt.req, pub)
			if tt.expectSuccess && err != nil {
				t.Errorf("expected success, got error: %v", err)
			}
			if !tt.expectSuccess && err == nil {
				t.Errorf("expected failure, got success")
			}
		})
	}
}
