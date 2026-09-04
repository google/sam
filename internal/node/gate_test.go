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
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/sam/api"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestConnectionGater(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Logf("failed to close store: %v", err)
		}
	}()

	cache, err := lru.New[string, int64](100)
	if err != nil {
		t.Fatal(err)
	}

	node := &SamNode{
		Store:          store,
		revokedPeers:   cache,
		BiscuitTimeout: 500 * time.Millisecond,
	}
	gater := &nodeConnGate{node: node}

	// Generate test peer IDs
	priv1, _, _ := crypto.GenerateEd25519Key(nil)
	peer1, _ := peer.IDFromPrivateKey(priv1)

	priv2, _, _ := crypto.GenerateEd25519Key(nil)
	peer2, _ := peer.IDFromPrivateKey(priv2)

	priv3, _, _ := crypto.GenerateEd25519Key(nil)
	peer3, _ := peer.IDFromPrivateKey(priv3)

	// Case 1: Peer is not banned
	if !gater.InterceptPeerDial(peer1) {
		t.Errorf("expected InterceptPeerDial to allow peer1")
	}
	if !gater.InterceptSecured(network.DirInbound, peer1, nil) {
		t.Errorf("expected InterceptSecured to allow peer1")
	}

	// Case 2: Peer is in revoked cache
	node.revokedPeers.Add(peer2.String(), time.Now().Unix())
	if gater.InterceptPeerDial(peer2) {
		t.Errorf("expected InterceptPeerDial to deny peer2 (in revoked cache)")
	}

	if gater.InterceptSecured(network.DirInbound, peer2, nil) {
		t.Errorf("expected InterceptSecured to deny peer2 (in revoked cache)")
	}

	// Case 3: a peer the control plane does not ban stays reachable, even
	// after another peer has been banned.
	if !gater.InterceptPeerDial(peer3) {
		t.Errorf("expected InterceptPeerDial to allow peer3")
	}
	if !gater.InterceptSecured(network.DirInbound, peer3, nil) {
		t.Errorf("expected InterceptSecured to allow peer3")
	}
}

// The revocation cache is seeded from the control plane's ban set at startup
// (Options.BannedPeerIDs, filled by SyncMeshConfig). Without that a restarted
// node would enforce no ban at all until the next MeshEvent_BANNED, which for
// a ban published while it was down never arrives.
func TestGaterEnforcesSeededBans(t *testing.T) {
	priv, _, _ := crypto.GenerateEd25519Key(nil)
	banned, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	otherPriv, _, _ := crypto.GenerateEd25519Key(nil)
	allowed, err := peer.IDFromPrivateKey(otherPriv)
	if err != nil {
		t.Fatal(err)
	}

	cache, err := lru.New[string, int64](100)
	if err != nil {
		t.Fatal(err)
	}
	node := &SamNode{revokedPeers: cache}
	// Mirrors what NewSamNode does with Options.BannedPeerIDs.
	node.revokedPeers.Add(banned.String(), time.Now().Unix())

	gater := &nodeConnGate{node: node}
	if gater.InterceptPeerDial(banned) {
		t.Error("a peer in the control plane's ban set must not be dialled")
	}
	if gater.InterceptSecured(network.DirInbound, banned, nil) {
		t.Error("a peer in the control plane's ban set must not be accepted")
	}
	if !gater.InterceptPeerDial(allowed) {
		t.Error("seeding a ban must not deny unrelated peers")
	}
}

// startBareNode brings up a SamNode without control plane/enrollment.
func startBareNode(t *testing.T, ctx context.Context) (*SamNode, func()) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewSamNode(Options{
		PrivKey:           priv,
		RouterAddrs:       nil,
		Store:             store,
		MeshID:            "test-mesh",
		DiscoveryInterval: "1s",
		ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
		EnableRelay:       false,
		NodeConfig:        &NodeConfigComplete{},
		KeyGracePeriod:    24 * time.Hour,
		AllowLoopback:     true,
		MonitorBootstrap:  2 * time.Minute,
		MonitorInterval:   1 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	node.BiscuitTimeout = 500 * time.Millisecond
	if err := node.Start(ctx); err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		_ = node.Teardown()
		_ = store.Close()
	}
	return node, cleanup
}

const testMCPProtocol = protocol.ID("/sam-test/mcp/1.0.0")

func TestHandleMCPStream_DumbPipeProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tools := []*mcp.Tool{
		{Name: "review_pr", Description: "Run a code review", InputSchema: map[string]any{"type": "object"}},
	}
	upstream := httptest.NewServer(newFakeMCPHandler(t, tools))
	defer upstream.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	// Init a real MCPService so session + aggregatedTools are populated; insert
	// directly to skip DHT advertisement.
	svc := &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: upstream.URL},
	}}
	if err := svc.Init(ctx); err != nil {
		t.Fatalf("MCPService.Init: %v", err)
	}
	nodeA.services.insertService(svc)
	t.Cleanup(func() { _ = svc.Teardown() })

	// Bypass biscuit auth by exposing HandleMCPStream on a test-only protocol.
	nodeA.Host.SetStreamHandler(testMCPProtocol, func(s network.Stream) {
		nodeA.HandleMCPStream(s, RequestContext{Target: "code-reviewer"})
	})

	if err := nodeB.Host.Connect(ctx, peer.AddrInfo{ID: nodeA.Host.ID(), Addrs: nodeA.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	s, err := nodeB.Host.NewStream(ctx, nodeA.Host.ID(), testMCPProtocol)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	defer func() { _ = s.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, NewStreamTransport(s), nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	found := false
	for _, n := range names {
		if n == "review_pr" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected tools/list to include %q; got %v", "review_pr", names)
	}

	// Dumb pipe: infra tools are NOT present.
	for _, n := range names {
		if n == "get_mesh_info" {
			t.Errorf("expected infra tool get_mesh_info to be absent in dumb pipe; got %v", names)
		}
	}
}

func TestHandleMCPStream_ForwarderRoutesCalls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tools := []*mcp.Tool{
		{Name: "echo", Description: "echo", InputSchema: map[string]any{"type": "object"}},
	}
	upstream := httptest.NewServer(newFakeMCPHandler(t, tools))
	defer upstream.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	svc := &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "svc"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: upstream.URL},
	}}
	if err := svc.Init(ctx); err != nil {
		t.Fatalf("MCPService.Init: %v", err)
	}
	nodeA.services.insertService(svc)
	t.Cleanup(func() { _ = svc.Teardown() })

	nodeA.Host.SetStreamHandler(testMCPProtocol, func(s network.Stream) {
		nodeA.HandleMCPStream(s, RequestContext{Target: "svc"})
	})

	if err := nodeB.Host.Connect(ctx, peer.AddrInfo{ID: nodeA.Host.ID(), Addrs: nodeA.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	s, err := nodeB.Host.NewStream(ctx, nodeA.Host.ID(), testMCPProtocol)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	defer func() { _ = s.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "tc", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, NewStreamTransport(s), nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"unused": true},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatal("expected non-empty Content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	// newFakeMCPHandler echoes "fake-result:<tool-name>" using the un-namespaced form.
	if tc.Text != "fake-result:echo" {
		t.Errorf("forwarder did not pass un-namespaced name; got %q", tc.Text)
	}
}
