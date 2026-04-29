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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

// SendMessageParams defines the parameters for the send_message tool.
type SendMessageParams struct {
	PeerID  string `json:"peer_id" jsonschema:"The Peer ID of the target agent"`
	Message string `json:"message" jsonschema:"The message content"`
}

// handleSendMessage implements the send_message tool.
func handleSendMessage(ctx context.Context, req *mcp.CallToolRequest, params SendMessageParams) (*mcp.CallToolResult, any, error) {
	response := fmt.Sprintf("Simulated sending message to %s: %s", params.PeerID, params.Message)

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: response},
		},
	}, nil, nil
}

// NewMCPHandler creates a new HTTP handler for the MCP server using the official SDK.
func NewMCPHandler(node *SamNode) http.Handler {
	// Create an MCP server.
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "sam-node-mcp",
		Version: "0.1.0",
	}, nil)

	// Add the send_message tool.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "send_message",
		Description: "Send a message to another agent in the mesh",
	}, handleSendMessage)

	// Add the mesh_pubsub_broadcast tool.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "mesh_pubsub_broadcast",
		Description: "Publish an event payload to a custom GossipSub topic",
	}, func(ctx context.Context, req *mcp.CallToolRequest, params struct {
		Topic   string `json:"topic" jsonschema:"GossipSub topic name"`
		Payload string `json:"payload" jsonschema:"Payload to publish"`
	}) (*mcp.CallToolResult, any, error) {
		node.mu.Lock()
		t, ok := node.topics[params.Topic]
		var err error
		if !ok {
			t, err = node.PubSub.Join(params.Topic)
			if err == nil {
				node.topics[params.Topic] = t
			}
		}
		node.mu.Unlock()
		if err != nil {
			return nil, nil, err
		}
		if err := t.Publish(ctx, []byte(params.Payload)); err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Published"},
			},
		}, nil, nil
	})

	// Add the poll_messages tool.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "poll_messages",
		Description: "Poll for incoming messages on custom GossipSub topics",
	}, func(ctx context.Context, req *mcp.CallToolRequest, params struct {
		Topic string `json:"topic" jsonschema:"GossipSub topic name"`
	}) (*mcp.CallToolResult, any, error) {
		node.mu.Lock()
		msgs := node.receivedMsgs[params.Topic]
		delete(node.receivedMsgs, params.Topic) // Clear on read!
		node.mu.Unlock()

		response := fmt.Sprintf("Messages on topic %s: %v", params.Topic, msgs)
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: response},
			},
		}, nil, nil
	})

	// Add the subscribe_topic tool.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "subscribe_topic",
		Description: "Subscribe to a custom GossipSub topic",
	}, func(ctx context.Context, req *mcp.CallToolRequest, params struct {
		Topic string `json:"topic" jsonschema:"GossipSub topic name"`
	}) (*mcp.CallToolResult, any, error) {
		if err := node.subscribeToTopic(ctx, params.Topic); err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Subscribed"},
			},
		}, nil, nil
	})

	// Add the get_mesh_info tool.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_mesh_info",
		Description: "Get information about the mesh network",
	}, func(ctx context.Context, req *mcp.CallToolRequest, params struct{}) (*mcp.CallToolResult, any, error) {
		if node == nil {
			return nil, nil, fmt.Errorf("node not initialized")
		}
		node.mu.Lock()
		knownCount := len(node.knownPeers)
		var knownPeers []string
		for p := range node.knownPeers {
			knownPeers = append(knownPeers, p)
		}
		node.mu.Unlock()

		peers := node.Host.Network().Peers()
		dhtSize := node.DHT.RoutingTable().Size()

		response := fmt.Sprintf("Known peers count: %d\nKnown peers list: %v\nConnected peers: %d\nDHT Routing Table size: %d\nHub Peer ID: %s", knownCount, knownPeers, len(peers), dhtSize, node.HubPeerID)

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: response},
			},
		}, nil, nil
	})

	// Add the connect_peer tool.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "connect_peer",
		Description: "Connect to a peer in the mesh",
	}, func(ctx context.Context, req *mcp.CallToolRequest, params struct {
		PeerAddr string `json:"peer_addr" jsonschema:"The full multiaddress of the peer to connect to"`
	}) (*mcp.CallToolResult, any, error) {
		ma, err := multiaddr.NewMultiaddr(params.PeerAddr)
		if err != nil {
			return nil, nil, err
		}
		addrInfo, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			return nil, nil, err
		}
		if err := node.Host.Connect(ctx, *addrInfo); err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Connected"},
			},
		}, nil, nil
	})

	// Create the streamable HTTP handler.
	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

	return handler
}

// CallMCPTool opens a stream to a remote peer, performs the handshake, and calls a tool.
func (n *SamNode) CallMCPTool(ctx context.Context, targetPeer peer.ID, toolName string, params any) (*mcp.CallToolResult, error) {
	var res *mcp.CallToolResult
	var err error
	maxRetries := 3
	backoff := 1 * time.Second

	for i := 0; i < maxRetries; i++ {
		res, err = n.callMCPToolOnce(ctx, targetPeer, toolName, params)
		if err == nil {
			return res, nil
		}
		logger.Warnf("[MCP] Tool call failed, retrying in %v: %v", backoff, err)
		time.Sleep(backoff)
		backoff *= 2
	}
	return nil, fmt.Errorf("failed after %d retries: %w", maxRetries, err)
}

func (n *SamNode) callMCPToolOnce(ctx context.Context, targetPeer peer.ID, toolName string, params any) (*mcp.CallToolResult, error) {
	// Open stream
	s, err := n.Host.NewStream(ctx, targetPeer, api.MCPProtocolID)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream to %s: %w", targetPeer, err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			logger.Errorf("[MCP] Failed to close stream: %v", err)
		}
	}()

	// Load this node's biscuit
	biscuitStr, err := n.Store.LoadIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed to load identity biscuit: %w", err)
	}

	// Marshal AuthFrame
	authFrame := api.AuthFrame{
		Biscuit: []byte(biscuitStr),
	}
	authBytes, _ := proto.Marshal(&authFrame)

	// Write AuthFrame
	writer := msgio.NewVarintWriter(s)
	if err := writer.WriteMsg(authBytes); err != nil {
		return nil, fmt.Errorf("failed to write auth frame to %s: %w", targetPeer, err)
	}

	// Read ACK
	reader := msgio.NewVarintReaderSize(s, 1024*64)
	msg, err := reader.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("failed to read auth response from %s: %w", targetPeer, err)
	}
	defer reader.ReleaseMsg(msg)

	var resp api.AuthResponse
	if err := proto.Unmarshal(msg, &resp); err != nil {
		return nil, fmt.Errorf("invalid auth response from %s: %w", targetPeer, err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("auth rejected by %s: %s", targetPeer, resp.Error)
	}

	// Handoff to SDK using custom transport
	transport := NewStreamTransport(s)
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "sam-node-mcp-client", Version: "0.1.0"}, nil)

	session, err := mcpClient.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect client: %w", err)
	}

	callParams := &mcp.CallToolParams{
		Name: toolName,
	}
	paramsBytes, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal params for tool %s: %w", toolName, err)
	}
	callParams.Arguments = paramsBytes // Assume it takes bytes or raw message!

	res, err := session.CallTool(ctx, callParams)
	if err != nil {
		return nil, fmt.Errorf("failed to call tool %s: %w", toolName, err)
	}

	return res, nil
}
