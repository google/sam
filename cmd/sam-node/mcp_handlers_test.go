// Copyright 2026 Google LLC
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
// node as caller, grants allow_mcp_tool("*"), and saves it to node's store.
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
		Name: api.FactMCPTool,
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
	rowsB, errB := nodeA.fetchRemoteToolCatalogue(ctx, nodeB.Host.ID())
	if errB != nil {
		t.Fatalf("fetch from B: %v", errB)
	}
	rowsC, errC := nodeA.fetchRemoteToolCatalogue(ctx, nodeC.Host.ID())
	if errC != nil {
		t.Fatalf("fetch from C: %v", errC)
	}

	gotNames := map[string]bool{}
	for _, tool := range append(rowsB, rowsC...) {
		gotNames[tool.Name] = true
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

func TestAppendFilteredRows_ServiceNameFilter(t *testing.T) {
	tools := []*mcp.Tool{
		{Name: "code-reviewer.review_pr"},
		{Name: "code-reviewer.add_comment"},
		{Name: "summarizer.summarize"},
		{Name: "send_message"}, // infra tool — no dot
	}

	rows := appendFilteredRows(nil, "peerB", tools, "code-reviewer")
	if len(rows) != 2 {
		t.Errorf("service filter: got %d rows, want 2; rows=%+v", len(rows), rows)
	}
	for _, r := range rows {
		if !strings.HasPrefix(r.ToolName, "code-reviewer.") {
			t.Errorf("row %+v doesn't match service prefix", r)
		}
	}
}

func TestAppendFilteredRows_AggregatedOnly(t *testing.T) {
	tools := []*mcp.Tool{
		{Name: "code-reviewer.review_pr"},
		{Name: "send_message"},
		{Name: "list_local_services"},
		{Name: "get_mesh_info"},
	}

	rows := appendFilteredRows(nil, "peerB", tools, "")
	if len(rows) != 1 {
		t.Errorf("aggregated-only filter: got %d rows, want 1; rows=%+v", len(rows), rows)
	}
	if rows[0].ToolName != "code-reviewer.review_pr" {
		t.Errorf("unexpected name %q", rows[0].ToolName)
	}
}

func TestAppendFilteredRows_PartialPrefixMatch(t *testing.T) {
	// "code" should NOT match "code-reviewer.review_pr" because the filter
	// requires exact service-name + "." prefix.
	tools := []*mcp.Tool{
		{Name: "code-reviewer.review_pr"},
		{Name: "code.something"},
	}
	rows := appendFilteredRows(nil, "peerB", tools, "code")
	if len(rows) != 1 || rows[0].ToolName != "code.something" {
		t.Errorf("expected exactly one row 'code.something'; got %+v", rows)
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

func TestNewMCPHandler_RegistersFindRemoteTools(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	srv := httptest.NewServer(NewMCPHandler(node))
	defer srv.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "tc", Version: "0.0.1"}, nil)
	transport := &mcp.SSEClientTransport{Endpoint: srv.URL + "/mcp/events"}
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
