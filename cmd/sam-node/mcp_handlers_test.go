// Copyright 2026 Google LLC
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"

	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// buildAndSaveBiscuit builds a biscuit signed with rootPriv that identifies
// node as caller, grants allow_mcp_server("*"), and saves it to node's store.
func buildAndSaveBiscuit(node *SamNode, rootPriv ed25519.PrivateKey) error {
	callerID := node.Host.ID().String()
	builder := biscuit.NewBuilder(rootPriv)
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(callerID)},
	}}); err != nil {
		return err
	}
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "client_peer_id",
		IDs:  []biscuit.Term{biscuit.String(callerID)},
	}}); err != nil {
		return err
	}
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactMCPServer,
		IDs:  []biscuit.Term{biscuit.String("*")},
	}}); err != nil {
		return err
	}
	bisc, err := builder.Build()
	if err != nil {
		return err
	}
	biscBytes, err := bisc.Serialize()
	if err != nil {
		return err
	}
	return node.Store.SaveIdentity(biscBytes)
}

func TestHandleFindRemoteTools_EmptyMesh_ReturnsEmptyArray(t *testing.T) {
	ctx, cancel := contextWithShortTimeout()
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	res, _, err := node.handleFindRemoteTools(ctx, &mcp.CallToolRequest{}, FindRemoteToolsParams{})
	if err != nil {
		t.Fatalf("handleFindRemoteTools: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatal("expected non-empty result content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &rows); err != nil {
		t.Fatalf("response not JSON array: %v (text: %q)", err, tc.Text)
	}
	if len(rows) != 0 {
		t.Errorf("expected empty results for empty mesh, got %d rows", len(rows))
	}
}

func TestHandleFindRemoteTools_SelfPeerRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	_, _, err := node.handleFindRemoteTools(ctx, &mcp.CallToolRequest{}, FindRemoteToolsParams{
		PeerID: node.Host.ID().String(),
	})
	if err == nil {
		t.Fatal("expected error when peer_id equals self peer ID")
	}
}

// contextWithShortTimeout returns a context with a small deadline so
// that tests fail fast if a libp2p dial hangs.
func contextWithShortTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 3*time.Second)
}

func TestHandleFindRemoteTools_SinglePeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tools := []*mcp.Tool{
		{Name: "review_pr", Description: "Run a code review", InputSchema: map[string]any{"type": "object"}},
		{Name: "add_comment", Description: "Add a comment", InputSchema: map[string]any{"type": "object"}},
	}
	hostedSrv := httptest.NewServer(newFakeMCPHandler(t, tools))
	defer hostedSrv.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeB.Host.ID(), Addrs: nodeB.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}
	if err := buildAndSaveBiscuit(nodeA, rootPriv); err != nil {
		t.Fatalf("buildAndSaveBiscuit: %v", err)
	}

	// B trusts the same root key used to sign A's biscuit.
	nodeB.keysMu.Lock()
	nodeB.trustedKeys = append(nodeB.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
	nodeB.keysMu.Unlock()

	// Register an MCP service on B with two tools.
	regReq := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: hostedSrv.URL},
	}
	if err := nodeB.RegisterService(ctx, regReq); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}

	res, _, err := nodeA.handleFindRemoteTools(ctx, &mcp.CallToolRequest{}, FindRemoteToolsParams{
		PeerID: nodeB.Host.ID().String(),
	})
	if err != nil {
		t.Fatalf("handleFindRemoteTools: %v", err)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	var rows []remoteToolRow
	if err := json.Unmarshal([]byte(tc.Text), &rows); err != nil {
		t.Fatalf("unmarshal: %v (text: %q)", err, tc.Text)
	}

	wantNames := map[string]bool{
		"code-reviewer.review_pr":   false,
		"code-reviewer.add_comment": false,
	}
	for _, row := range rows {
		if row.PeerID != nodeB.Host.ID().String() {
			t.Errorf("row has peer_id %q, want %q", row.PeerID, nodeB.Host.ID().String())
		}
		if _, ok := wantNames[row.ToolName]; ok {
			wantNames[row.ToolName] = true
		}
	}
	for name, found := range wantNames {
		if !found {
			t.Errorf("expected tool %q in response, not found; rows=%+v", name, rows)
		}
	}
}

func TestHandleFindRemoteTools_MeshWide(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// B hosts "code-reviewer", C hosts "summarizer".
	bTools := []*mcp.Tool{
		{Name: "review_pr", Description: "review", InputSchema: map[string]any{"type": "object"}},
	}
	cTools := []*mcp.Tool{
		{Name: "summarize", Description: "summarize", InputSchema: map[string]any{"type": "object"}},
	}
	bSrv := httptest.NewServer(newFakeMCPHandler(t, bTools))
	defer bSrv.Close()
	cSrv := httptest.NewServer(newFakeMCPHandler(t, cTools))
	defer cSrv.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()
	nodeC, cleanupC := startBareNode(t, ctx)
	defer cleanupC()

	// Connect A to both B and C, and set up biscuit auth so A's stream
	// to B/C passes WithBiscuitAuth.
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen root: %v", err)
	}
	if err := buildAndSaveBiscuit(nodeA, rootPriv); err != nil {
		t.Fatalf("buildAndSaveBiscuit: %v", err)
	}
	for _, target := range []*SamNode{nodeB, nodeC} {
		if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: target.Host.ID(), Addrs: target.Host.Addrs()}); err != nil {
			t.Fatalf("connect to %s: %v", target.Host.ID(), err)
		}
		target.keysMu.Lock()
		target.trustedKeys = append(target.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
		target.keysMu.Unlock()
	}

	if err := nodeB.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: bSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService B: %v", err)
	}
	if err := nodeC.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "summarizer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: cSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService C: %v", err)
	}

	// Direct fan-out test: invoke fetchRemoteToolCatalogue for both peers,
	// confirm both return their tools. This isolates the lower-level path
	// from DHT convergence concerns.
	rowsB, errB := nodeA.fetchRemoteToolCatalogue(ctx, nodeB.Host.ID(), "")
	if errB != nil {
		t.Fatalf("fetch from B: %v", errB)
	}
	rowsC, errC := nodeA.fetchRemoteToolCatalogue(ctx, nodeC.Host.ID(), "")
	if errC != nil {
		t.Fatalf("fetch from C: %v", errC)
	}

	gotNames := map[string]bool{}
	for _, tool := range append(rowsB, rowsC...) {
		gotNames[tool.ToolName] = true
	}
	if !gotNames["code-reviewer.review_pr"] {
		t.Errorf("missing code-reviewer.review_pr; got %v", gotNames)
	}
	if !gotNames["summarizer.summarize"] {
		t.Errorf("missing summarizer.summarize; got %v", gotNames)
	}
}

func TestHandleFindRemoteTools_MeshWideViaHandler(t *testing.T) {
	t.Skip("requires DHT convergence; isolated libp2p hosts cannot form a functional provider store. Covered by e2e tests.")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bSrv := httptest.NewServer(newFakeMCPHandler(t, []*mcp.Tool{
		{Name: "review_pr", Description: "x", InputSchema: map[string]any{"type": "object"}},
	}))
	defer bSrv.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := buildAndSaveBiscuit(nodeA, rootPriv); err != nil {
		t.Fatalf("buildAndSaveBiscuit: %v", err)
	}
	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeB.Host.ID(), Addrs: nodeB.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	nodeB.keysMu.Lock()
	nodeB.trustedKeys = append(nodeB.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
	nodeB.keysMu.Unlock()

	if err := nodeB.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: bSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}

	// Give the DHT a moment to record the provider.
	time.Sleep(5 * time.Second)

	res, _, err := nodeA.handleFindRemoteTools(ctx, &mcp.CallToolRequest{}, FindRemoteToolsParams{})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	tc := res.Content[0].(*mcp.TextContent)
	var rows []remoteToolRow
	if err := json.Unmarshal([]byte(tc.Text), &rows); err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range rows {
		if r.ToolName == "code-reviewer.review_pr" && r.PeerID == nodeB.Host.ID().String() {
			found = true
		}
	}
	if !found {
		t.Errorf("expected code-reviewer.review_pr from B; got rows=%+v", rows)
	}
}

func TestHandleFindRemoteTools_PartialFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("network/dial: skipped in -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cSrv := httptest.NewServer(newFakeMCPHandler(t, []*mcp.Tool{
		{Name: "summarize", Description: "x", InputSchema: map[string]any{"type": "object"}},
	}))
	defer cSrv.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeC, cleanupC := startBareNode(t, ctx)
	defer cleanupC()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := buildAndSaveBiscuit(nodeA, rootPriv); err != nil {
		t.Fatalf("buildAndSaveBiscuit: %v", err)
	}

	// A connects to C only; B is a fictional peer ID that won't resolve.
	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeC.Host.ID(), Addrs: nodeC.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	nodeC.keysMu.Lock()
	nodeC.trustedKeys = append(nodeC.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
	nodeC.keysMu.Unlock()

	if err := nodeC.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "summarizer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: cSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}

	// Generate a fictitious peer ID from a fresh keypair we never connect to.
	_, fakePub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	fictitiousPID, err := peer.IDFromPublicKey(fakePub)
	if err != nil {
		t.Fatal(err)
	}

	rows := nodeA.fanOutFetch(ctx, []peer.ID{nodeC.Host.ID(), fictitiousPID}, "")

	gotSummarizer := false
	for _, r := range rows {
		if r.ToolName == "summarizer.summarize" {
			gotSummarizer = true
		}
	}
	if !gotSummarizer {
		t.Errorf("expected summarizer.summarize from C even with B unreachable; got %+v", rows)
	}
}

func buildAndSaveCustomBiscuit(node *SamNode, rootPriv ed25519.PrivateKey, allowedServices []string) error {
	callerID := node.Host.ID().String()
	builder := biscuit.NewBuilder(rootPriv)
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(callerID)},
	}}); err != nil {
		return err
	}
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "client_peer_id",
		IDs:  []biscuit.Term{biscuit.String(callerID)},
	}}); err != nil {
		return err
	}
	for _, svc := range allowedServices {
		if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactMCPServer,
			IDs:  []biscuit.Term{biscuit.String(svc)},
		}}); err != nil {
			return err
		}
	}
	bisc, err := builder.Build()
	if err != nil {
		return err
	}
	biscBytes, err := bisc.Serialize()
	if err != nil {
		return err
	}
	return node.Store.SaveIdentity(biscBytes)
}

func TestFetchRemoteToolCatalogue_AuthRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cSrv := httptest.NewServer(newFakeMCPHandler(t, []*mcp.Tool{
		{Name: "summarize", Description: "x", InputSchema: map[string]any{"type": "object"}},
	}))
	defer cSrv.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeC, cleanupC := startBareNode(t, ctx)
	defer cleanupC()

	rootPubEd, rootPrivEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	
	// Create a biscuit that DOES NOT allow "summarizer", only "some_other_service".
	// By baseline rules, it will STILL allow the catalog fetch.
	if err := buildAndSaveCustomBiscuit(nodeA, rootPrivEd, []string{"some_other_service"}); err != nil {
		t.Fatalf("buildAndSaveCustomBiscuit: %v", err)
	}

	// Trust the key in Node C
	nodeC.keysMu.Lock()
	nodeC.trustedKeys = append(nodeC.trustedKeys, TrustedKey{Key: rootPubEd, ReceivedAt: time.Now()})
	nodeC.keysMu.Unlock()

	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeC.Host.ID(), Addrs: nodeC.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}

	if err := nodeC.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "summarizer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: cSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}

	// Fetching tools from C should succeed for the catalog, but fail auth for "summarizer"
	rows, err := nodeA.fetchRemoteToolCatalogue(ctx, nodeC.Host.ID(), "")
	if err != nil {
		t.Fatalf("fetchRemoteToolCatalogue returned unexpected overall error: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 row with error, got %d: %+v", len(rows), rows)
	}

	row := rows[0]
	if row.ToolName != "summarizer" {
		t.Errorf("expected ToolName 'summarizer', got %q", row.ToolName)
	}
	if !strings.Contains(row.Error, "auth rejected") {
		t.Errorf("expected Error to contain 'auth rejected', got %q", row.Error)
	}
}

func TestNewMCPHandler_RegistersFindRemoteTools(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	srv := httptest.NewServer(NewMCPHandler(node))
	defer srv.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "tc", Version: "0.0.1"}, nil)
	transport := &mcp.StreamableClientTransport{Endpoint: srv.URL + "/mcp"}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	found := false
	for _, tl := range res.Tools {
		if tl.Name == "find_remote_tools" {
			found = true
		}
	}
	if !found {
		var names []string
		for _, tl := range res.Tools {
			names = append(names, tl.Name)
		}
		t.Errorf("find_remote_tools missing from sidecar tools/list; got %v", names)
	}
}

func TestHandleDescribeRemoteTool_EmptyPeerID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	_, _, err := node.handleDescribeRemoteTool(ctx, &mcp.CallToolRequest{}, DescribeRemoteToolParams{
		ToolName: "code-reviewer.review_pr",
	})
	if err == nil {
		t.Fatal("expected error for empty peer_id")
	}
}

func TestHandleDescribeRemoteTool_EmptyToolName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	_, _, err := node.handleDescribeRemoteTool(ctx, &mcp.CallToolRequest{}, DescribeRemoteToolParams{
		PeerID: "12D3KooWFakePeerID",
	})
	if err == nil {
		t.Fatal("expected error for empty tool_name")
	}
}

func TestHandleDescribeRemoteTool_NonNamespacedRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	_, _, err := node.handleDescribeRemoteTool(ctx, &mcp.CallToolRequest{}, DescribeRemoteToolParams{
		PeerID:   node.Host.ID().String(),
		ToolName: "send_message", // no dot
	})
	if err == nil {
		t.Fatal("expected error for tool_name without '.'")
	}
	if !strings.Contains(err.Error(), "service.tool") {
		t.Errorf("error %q does not explain the namespacing requirement", err.Error())
	}
}

func TestHandleDescribeRemoteTool_SelfPeerRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	_, _, err := node.handleDescribeRemoteTool(ctx, &mcp.CallToolRequest{}, DescribeRemoteToolParams{
		PeerID:   node.Host.ID().String(),
		ToolName: "code-reviewer.review_pr",
	})
	if err == nil {
		t.Fatal("expected error when peer_id equals self peer ID")
	}
}

func TestHandleDescribeRemoteTool_InvalidPeerID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	_, _, err := node.handleDescribeRemoteTool(ctx, &mcp.CallToolRequest{}, DescribeRemoteToolParams{
		PeerID:   "not-a-valid-peer-id",
		ToolName: "code-reviewer.review_pr",
	})
	if err == nil {
		t.Fatal("expected error for malformed peer_id")
	}
}

func TestHandleDescribeRemoteTool_RoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeB.Host.ID(), Addrs: nodeB.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}
	if err := buildAndSaveBiscuit(nodeA, rootPriv); err != nil {
		t.Fatalf("buildAndSaveBiscuit: %v", err)
	}
	nodeB.keysMu.Lock()
	nodeB.trustedKeys = append(nodeB.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
	nodeB.keysMu.Unlock()

	tools := []*mcp.Tool{
		{
			Name:        "review_pr",
			Description: "Run a code review",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []any{"pr_url"},
				"properties": map[string]any{
					"pr_url": map[string]any{"type": "string"},
				},
			},
			OutputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"summary": map[string]any{"type": "string"},
				},
			},
		},
	}
	hostedSrv := httptest.NewServer(newFakeMCPHandler(t, tools))
	defer hostedSrv.Close()

	regReq := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: hostedSrv.URL},
	}
	if err := nodeB.RegisterService(ctx, regReq); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}
	defer func() { _ = nodeB.UnregisterService(ctx, "code-reviewer") }()

	res, _, err := nodeA.handleDescribeRemoteTool(ctx, &mcp.CallToolRequest{}, DescribeRemoteToolParams{
		PeerID:   nodeB.Host.ID().String(),
		ToolName: "code-reviewer.review_pr",
	})
	if err != nil {
		t.Fatalf("handleDescribeRemoteTool: %v", err)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}

	var desc remoteToolDescription
	if err := json.Unmarshal([]byte(tc.Text), &desc); err != nil {
		t.Fatalf("unmarshal: %v (text: %q)", err, tc.Text)
	}
	if desc.PeerID != nodeB.Host.ID().String() {
		t.Errorf("PeerID = %q, want %q", desc.PeerID, nodeB.Host.ID().String())
	}
	if desc.ToolName != "code-reviewer.review_pr" {
		t.Errorf("ToolName = %q, want %q", desc.ToolName, "code-reviewer.review_pr")
	}
	if desc.Description != "Run a code review" {
		t.Errorf("Description = %q, want %q", desc.Description, "Run a code review")
	}
	inSchema, ok := desc.InputSchema.(map[string]any)
	if !ok {
		t.Fatalf("InputSchema type = %T, want map[string]any", desc.InputSchema)
	}
	if inSchema["type"] != "object" {
		t.Errorf("InputSchema.type = %v, want 'object'", inSchema["type"])
	}
	outSchema, ok := desc.OutputSchema.(map[string]any)
	if !ok {
		t.Fatalf("OutputSchema type = %T, want map[string]any", desc.OutputSchema)
	}
	if outSchema["type"] != "object" {
		t.Errorf("OutputSchema.type = %v, want 'object'", outSchema["type"])
	}
}

func TestHandleDescribeRemoteTool_RoundTrip_UnknownTool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeB.Host.ID(), Addrs: nodeB.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}
	if err := buildAndSaveBiscuit(nodeA, rootPriv); err != nil {
		t.Fatalf("buildAndSaveBiscuit: %v", err)
	}
	nodeB.keysMu.Lock()
	nodeB.trustedKeys = append(nodeB.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
	nodeB.keysMu.Unlock()

	tools := []*mcp.Tool{
		{Name: "review_pr", Description: "x", InputSchema: map[string]any{"type": "object"}},
	}
	hostedSrv := httptest.NewServer(newFakeMCPHandler(t, tools))
	defer hostedSrv.Close()
	if err := nodeB.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: hostedSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}
	defer func() { _ = nodeB.UnregisterService(ctx, "code-reviewer") }()

	_, _, err = nodeA.handleDescribeRemoteTool(ctx, &mcp.CallToolRequest{}, DescribeRemoteToolParams{
		PeerID:   nodeB.Host.ID().String(),
		ToolName: "code-reviewer.does-not-exist",
	})
	if err == nil {
		t.Fatal("expected error from peer when tool is not registered")
	}
	wantError := "tool not found on peer"
	if err.Error() != wantError {
		t.Errorf("error %q != %q", err.Error(), wantError)
	}
}

func TestNewMCPHandler_RegistersDescribeRemoteTool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	srv := httptest.NewServer(NewMCPHandler(node))
	defer srv.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "tc", Version: "0.0.1"}, nil)
	transport := &mcp.StreamableClientTransport{Endpoint: srv.URL + "/mcp"}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	found := false
	for _, tl := range res.Tools {
		if tl.Name == "describe_remote_tool" {
			found = true
		}
	}
	if !found {
		var names []string
		for _, tl := range res.Tools {
			names = append(names, tl.Name)
		}
		t.Errorf("describe_remote_tool missing from sidecar tools/list; got %v", names)
	}
}

// newFakeMCPHandler returns an http.Handler serving a tiny MCP server over
// streamable-http with the given tools registered.
func newFakeMCPHandler(t *testing.T, tools []*mcp.Tool) http.Handler {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "0.0.1"}, nil)
	for _, tool := range tools {
		toolCopy := tool
		srv.AddTool(toolCopy, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "fake-result:" + toolCopy.Name}},
			}, nil
		})
	}
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
}
