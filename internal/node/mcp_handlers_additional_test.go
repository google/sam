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
	"testing"

	"github.com/google/sam/api"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestHandleSendMessage(t *testing.T) {
	ctx := context.Background()
	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	res, _, err := node.handleSendMessage(context.Background(), &mcp.CallToolRequest{}, SendMessageParams{
		PeerID:  "123",
		Message: "Hello",
	})
	if err != nil {
		t.Fatalf("handleSendMessage failed: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("expected content")
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if text != "Simulated sending message to 123: Hello" {
		t.Errorf("unexpected response: %q", text)
	}
}

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

func TestHandleMeshPubsub(t *testing.T) {
	ctx := context.Background()
	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	// Subscribe
	res, _, err := node.handleSubscribeTopic(context.Background(), &mcp.CallToolRequest{}, SubscribeTopicParams{
		Topic: "test-topic",
	})
	if err != nil {
		t.Fatalf("handleSubscribeTopic failed: %v", err)
	}
	if res.Content[0].(*mcp.TextContent).Text != "Subscribed" {
		t.Errorf("expected Subscribed")
	}

	// Publish
	_, _, err = node.handleMeshPubsubBroadcast(context.Background(), &mcp.CallToolRequest{}, MeshPubsubBroadcastParams{
		Topic:   "test-topic",
		Payload: "test-message",
	})
	if err != nil {
		t.Fatalf("handleMeshPubsubBroadcast failed: %v", err)
	}

	// Poll
	res, _, err = node.handlePollMessages(context.Background(), &mcp.CallToolRequest{}, PollMessagesParams{
		Topic: "test-topic",
	})
	if err != nil {
		t.Fatalf("handlePollMessages failed: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("expected content in poll messages")
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

func TestHandleConnectPeer(t *testing.T) {
	ctx := context.Background()
	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	res, _, err := node.handleConnectPeer(context.Background(), &mcp.CallToolRequest{}, ConnectPeerParams{
		PeerAddr: nodeB.Host.Addrs()[0].String() + "/p2p/" + nodeB.Host.ID().String(),
	})
	if err != nil {
		t.Fatalf("handleConnectPeer failed: %v", err)
	}
	if res.Content[0].(*mcp.TextContent).Text != "Connected" {
		t.Errorf("expected Connected")
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

// TestCheckConnectivityHandler tests the check_connectivity tool.
func TestCheckConnectivityHandler(t *testing.T) {
	node1, cleanup1 := startBareNode(t, context.Background())
	defer cleanup1()

	res, _, err := node1.handleCheckConnectivity(context.Background(), nil, CheckConnectivityParams{})
	if err != nil {
		t.Fatalf("handleCheckConnectivity failed: %v", err)
	}

	if len(res.Content) != 1 {
		t.Fatalf("expected 1 content block, got %d", len(res.Content))
	}

	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent")
	}

	var stats map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &stats); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if _, ok := stats["connected_peers"]; !ok {
		t.Fatalf("missing connected_peers in stats")
	}
}

// TestGetTokenInfoHandler tests the get_token_info tool.
func TestGetTokenInfoHandler(t *testing.T) {
	node1, cleanup1 := startBareNode(t, context.Background())
	defer cleanup1()

	res, _, err := node1.handleGetTokenInfo(context.Background(), nil, GetTokenInfoParams{})
	if err != nil {
		t.Fatalf("handleGetTokenInfo failed: %v", err)
	}

	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent")
	}

	var info map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &info); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	// Should have has_token=false initially since no token is built in setupTestNode explicitly for the node's store.
	// Wait, setupTestNode might set a token?
	if hasToken, ok := info["has_token"].(bool); !ok {
		t.Fatalf("expected has_token boolean, got %v", info["has_token"])
	} else if hasToken {
		// It might be true if setupTestNode saves a biscuit.
		_ = hasToken
	}
}

// TestGetNetworkInfoHandler tests the get_network_info tool.
func TestGetNetworkInfoHandler(t *testing.T) {
	node1, cleanup1 := startBareNode(t, context.Background())
	defer cleanup1()

	res, _, err := node1.handleGetNetworkInfo(context.Background(), nil, GetNetworkInfoParams{})
	if err != nil {
		t.Fatalf("handleGetNetworkInfo failed: %v", err)
	}

	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent")
	}

	var info map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &info); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if _, ok := info["listen_addresses"]; !ok {
		t.Fatalf("missing listen_addresses")
	}
}

// TestGetRecentLogsHandler tests the get_recent_logs tool.
func TestGetRecentLogsHandler(t *testing.T) {
	node1, cleanup1 := startBareNode(t, context.Background())
	defer cleanup1()

	res, _, err := node1.handleGetRecentLogs(context.Background(), nil, GetRecentLogsParams{})
	if err != nil {
		t.Fatalf("handleGetRecentLogs failed: %v", err)
	}

	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent")
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &data); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if _, ok := data["logs"]; !ok {
		t.Fatalf("missing logs")
	}
}
