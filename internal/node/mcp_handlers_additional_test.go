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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/sam/api"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestHandleDiscoverRemoteServices(t *testing.T) {
	ctx := context.Background()
	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	res, _, err := node.handleDiscoverRemoteServices(context.Background(), &mcp.CallToolRequest{}, DiscoverRemoteServicesParams{
		Type: "mcp",
		Name: "test-service",
	})
	if err != nil {
		t.Fatalf("handleDiscoverRemoteServices failed: %v", err)
	}

	var providers []*api.DiscoveredProvider
	text := res.Content[0].(*mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &providers); err != nil {
		t.Fatalf("failed to unmarshal providers: %v", err)
	}
	if len(providers) != 0 {
		t.Errorf("expected 0 providers, got %d", len(providers))
	}

	// Test invalid type
	_, _, err = node.handleDiscoverRemoteServices(context.Background(), &mcp.CallToolRequest{}, DiscoverRemoteServicesParams{
		Type: "invalid",
	})
	if err == nil {
		t.Errorf("expected error for invalid service type")
	}
}

func TestHandleGetMeshInfo(t *testing.T) {
	ctx := context.Background()
	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	res, _, err := node.handleGetMeshInfo(context.Background(), &mcp.CallToolRequest{}, GetMeshInfoParams{})
	if err != nil {
		t.Fatalf("handleGetMeshInfo failed: %v", err)
	}

	text := res.Content[0].(*mcp.TextContent).Text
	var info map[string]any
	if err := json.Unmarshal([]byte(text), &info); err != nil {
		t.Fatalf("failed to parse mesh info: %v", err)
	}

	if _, ok := info["connected_peers"]; !ok {
		t.Errorf("missing connected_peers in mesh info")
	}
	if _, ok := info["dht_size"]; !ok {
		t.Errorf("missing dht_size in mesh info")
	}
}

func TestConnectPeer(t *testing.T) {
	ctx := context.Background()
	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	err := node.connectPeer(context.Background(), nodeB.Host.Addrs()[0].String()+"/p2p/"+nodeB.Host.ID().String())
	if err != nil {
		t.Fatalf("connectPeer failed: %v", err)
	}
}

func TestHandleCallRemoteServer(t *testing.T) {
	ctx := context.Background()
	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	_, _, err := node.handleCallRemoteTool(context.Background(), &mcp.CallToolRequest{}, CallRemoteToolParams{
		PeerID:   "invalid_peer_id",
		ToolName: "test",
	})
	if err == nil {
		t.Errorf("expected error for invalid peer id")
	}
}

// TestConnectivityStats tests the logic behind GET /debug/connectivity.
func TestConnectivityStats(t *testing.T) {
	node1, cleanup1 := startBareNode(t, context.Background())
	defer cleanup1()

	stats := node1.connectivityStats(context.Background(), "")
	if stats.ConnectedPeers < 0 || stats.TotalKnownPeers < 0 {
		t.Fatalf("nonsensical peer counts: %+v", stats)
	}

	invalid := node1.connectivityStats(context.Background(), "not-a-peer-id")
	if invalid.PingError == nil || !*invalid.PingError || invalid.PingErrorMsg != "invalid peer id" {
		t.Fatalf("expected invalid peer id ping error, got %+v", invalid)
	}
}

// TestTokenInfo tests the logic behind GET /debug/token-info.
func TestTokenInfo(t *testing.T) {
	node1, cleanup1 := startBareNode(t, context.Background())
	defer cleanup1()

	info := node1.tokenInfo()
	if info.HasToken {
		t.Fatalf("bare node should have no token, got %+v", info)
	}
}

// TestNetworkInfo tests the logic behind GET /debug/network-info.
func TestNetworkInfo(t *testing.T) {
	node1, cleanup1 := startBareNode(t, context.Background())
	defer cleanup1()

	info := node1.networkInfo()
	if len(info.ListenAddresses) == 0 {
		t.Fatalf("expected listen addresses, got %+v", info)
	}
	if len(info.AnnouncedAddresses) == 0 {
		t.Fatalf("expected announced addresses, got %+v", info)
	}
}

// TestDebugHandlerHTTP exercises the /debug mux itself: routing, method
// gating, and request validation.
func TestDebugHandlerHTTP(t *testing.T) {
	node1, cleanup1 := startBareNode(t, context.Background())
	defer cleanup1()

	handler := newDebugHandler(node1)

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	for _, path := range []string{"/debug/mesh-info", "/debug/connectivity", "/debug/network-info", "/debug/token-info", "/debug/logs"} {
		rec := get(path)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: got %d, want 200 (body: %s)", path, rec.Code, rec.Body.String())
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Errorf("GET %s: invalid JSON: %v", path, err)
		}
	}

	networkInfo := get("/debug/network-info")
	if !strings.Contains(networkInfo.Body.String(), `"announced_addresses"`) {
		t.Fatalf("network info response does not contain announced_addresses: %s", networkInfo.Body.String())
	}
	if strings.Contains(networkInfo.Body.String(), `"observed_addresses"`) {
		t.Fatalf("network info response still contains observed_addresses: %s", networkInfo.Body.String())
	}
	var info networkInfoResponse
	if err := json.Unmarshal(networkInfo.Body.Bytes(), &info); err != nil {
		t.Fatalf("decode network info response: %v", err)
	}
	if len(info.AnnouncedAddresses) == 0 {
		t.Fatalf("network info response has no announced_addresses: %s", networkInfo.Body.String())
	}

	rec := get("/debug/connect-peer")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /debug/connect-peer: got %d, want 405", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/debug/connect-peer", strings.NewReader("not json")))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /debug/connect-peer with bad body: got %d, want 400", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/debug/connect-peer", strings.NewReader("{}")))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /debug/connect-peer without peer_addr: got %d, want 400", rec.Code)
	}

	// A half-built node refuses loudly instead of panicking.
	rec = httptest.NewRecorder()
	newDebugHandler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/logs", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /debug/logs on nil node: got %d, want 503", rec.Code)
	}
}
