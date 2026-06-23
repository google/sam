package main

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
		PeerID: "123",
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
	res, _, err = node.handleMeshPubsubBroadcast(context.Background(), &mcp.CallToolRequest{}, MeshPubsubBroadcastParams{
		Topic: "test-topic",
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
	
	_, _, err := node.handleCallRemoteServer(context.Background(), &mcp.CallToolRequest{}, CallRemoteServerParams{
		PeerID: "invalid_peer_id",
		ServerName: "test",
	})
	if err == nil {
		t.Errorf("expected error for invalid peer id")
	}
}
