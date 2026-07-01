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
	_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: "target_unrestricted"}})
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
		Name: "granted_service_all_types",
		IDs:  []biscuit.Term{},
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
		"mcp://code-reviewer/review_pr":   false,
		"mcp://code-reviewer/add_comment": false,
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

	// B hosts "code-reviewer", C hosts "mcp:summarizer", D hosts "plugin:linter".
	bTools := []*mcp.Tool{
		{Name: "review_pr", Description: "review", InputSchema: map[string]any{"type": "object"}},
	}
	cTools := []*mcp.Tool{
		{Name: "summarize", Description: "summarize", InputSchema: map[string]any{"type": "object"}},
	}
	dTools := []*mcp.Tool{
		{Name: "lint", Description: "lint", InputSchema: map[string]any{"type": "object"}},
	}
	bSrv := httptest.NewServer(newFakeMCPHandler(t, bTools))
	defer bSrv.Close()
	cSrv := httptest.NewServer(newFakeMCPHandler(t, cTools))
	defer cSrv.Close()
	dSrv := httptest.NewServer(newFakeMCPHandler(t, dTools))
	defer dSrv.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()
	nodeC, cleanupC := startBareNode(t, ctx)
	defer cleanupC()
	nodeD, cleanupD := startBareNode(t, ctx)
	defer cleanupD()

	// Connect A to B, C, and D, and set up biscuit auth so A's stream passes WithBiscuitAuth.
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen root: %v", err)
	}
	if err := buildAndSaveBiscuit(nodeA, rootPriv); err != nil {
		t.Fatalf("buildAndSaveBiscuit: %v", err)
	}
	for _, target := range []*SamNode{nodeB, nodeC, nodeD} {
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
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "mcp://summarizer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: cSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService C: %v", err)
	}
	if err := nodeD.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "plugin://linter"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: dSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService D: %v", err)
	}

	// Direct fan-out test: invoke fetchRemoteToolCatalogue for peers,
	// confirm they return their tools.
	rowsB, errB := nodeA.fetchRemoteToolCatalogue(ctx, nodeB.Host.ID(), "")
	if errB != nil {
		t.Fatalf("fetch from B: %v", errB)
	}
	rowsC, errC := nodeA.fetchRemoteToolCatalogue(ctx, nodeC.Host.ID(), "")
	if errC != nil {
		t.Fatalf("fetch from C: %v", errC)
	}
	rowsD, errD := nodeA.fetchRemoteToolCatalogue(ctx, nodeD.Host.ID(), "")
	if errD != nil {
		t.Fatalf("fetch from D: %v", errD)
	}

	gotNames := map[string]bool{}
	for _, tool := range append(append(rowsB, rowsC...), rowsD...) {
		gotNames[tool.ToolName] = true
	}

	// Test permutation 1: no prefix gets "mcp://" automatically prepended.
	if !gotNames["mcp://code-reviewer/review_pr"] {
		t.Errorf("missing mcp://code-reviewer/review_pr; got %v", gotNames)
	}
	// Test permutation 2: "mcp://" prefix is preserved.
	if !gotNames["mcp://summarizer/summarize"] {
		t.Errorf("missing mcp://summarizer/summarize; got %v", gotNames)
	}
	// Test permutation 3: custom namespace prefix is preserved.
	if !gotNames["plugin://linter/lint"] {
		t.Errorf("missing plugin://linter/lint; got %v", gotNames)
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
		if r.ToolName == "mcp://summarizer/summarize" {
			gotSummarizer = true
		}
	}
	if !gotSummarizer {
		t.Errorf("expected mcp://summarizer/summarize from C even with B unreachable; got %+v", rows)
	}
}

func buildAndSaveCustomBiscuit(node *SamNode, rootPriv ed25519.PrivateKey, allowedServices []string) error {
	callerID := node.Host.ID().String()
	builder := biscuit.NewBuilder(rootPriv)
	err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: "target_unrestricted"}})
	if err != nil {
		return err
	}
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
		parts := strings.SplitN(svc, ":", 2)
		opType := parts[0]
		opName := "*"
		if len(parts) > 1 {
			opName = parts[1]
		}
		if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: "granted_service_exact",
			IDs:  []biscuit.Term{biscuit.String(opType), biscuit.String(opName)},
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
	if row.ToolName != "mcp://summarizer" {
		t.Errorf("expected ToolName 'mcp://summarizer', got %q", row.ToolName)
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
		ToolName: "code-reviewer/review_pr",
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
	if !strings.Contains(err.Error(), "service/tool") {
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
		ToolName: "mcp://code-reviewer/review_pr",
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
		ToolName: "mcp://code-reviewer/review_pr",
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
		ToolName: "mcp://code-reviewer/review_pr",
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
	if desc.ToolName != "mcp://code-reviewer/review_pr" {
		t.Errorf("ToolName = %q, want %q", desc.ToolName, "mcp://code-reviewer/review_pr")
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
		ToolName: "mcp://code-reviewer/does-not-exist",
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
