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
	"google.golang.org/protobuf/proto"
)

// meshInstructions tells connecting clients a mesh is reachable here and how
// the find → describe → call flow works. Sent at initialize time.
const meshInstructions = `This MCP server connects this node to a SAM mesh: a network of remote agents that host their own MCP tools. The tools listed here are infrastructure for reaching tools on other peers when no local tool or capability covers the task.

Reach into the mesh only when the needed tool isn't available locally. To do so:
  1. find_remote_tools — discover what tools exist across the mesh (returns peer_id + namespaced tool_name + description). Optionally narrow by service_name or peer_id.
  2. describe_remote_tool — fetch a specific tool's input_schema before calling it. Always do this so you know the argument shape.
  3. call_remote_tool — invoke it. Pass peer_id, the namespaced tool_name, and arguments as a JSON object whose keys match the input_schema from step 2 (not a stringified blob).

Other useful tools: discover_remote_services browses services by type, get_mesh_info reports connected peers and mesh state, list_local_services shows what this node hosts.

Remote tool names are namespaced as '<service>.<tool>' (e.g. 'code-reviewer.review_pr'). Prefer discovering and describing a tool before calling it rather than guessing arguments.`

// NewMCPHandler creates a new HTTP handler for the MCP server using the official SDK.
func NewMCPHandler(node *SamNode) http.Handler {
	// Create an MCP server.
	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "sam-node-mcp",
		Version: "0.1.0",
	}, &mcp.ServerOptions{Instructions: meshInstructions})

	// Add the send_message tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "send_message",
		Description: "Send a message to another agent in the mesh",
	}, node.handleSendMessage)

	// Add list_local_services tool
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "list_local_services",
		Description: "List services registered on the local node. Optionally filter by type.",
	}, node.handleListLocalServices)

	// Add discover_remote_services tool
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "discover_remote_services",
		Description: "Discover remote services in the mesh. Provide only `type` to browse every reachable service of that type (returns name + description for each); add `name` to target a specific service.",
	}, node.handleDiscoverRemoteServices)

	// Add the mesh_pubsub_broadcast tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "mesh_pubsub_broadcast",
		Description: "Publish an event payload to a custom GossipSub topic",
	}, node.handleMeshPubsubBroadcast)

	// Add the poll_messages tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "poll_messages",
		Description: "Poll for incoming messages on custom GossipSub topics",
	}, node.handlePollMessages)

	// Add the subscribe_topic tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "subscribe_topic",
		Description: "Subscribe to a custom GossipSub topic",
	}, node.handleSubscribeTopic)

	// Add the get_mesh_info tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_mesh_info",
		Description: "Get information about the mesh network",
	}, node.handleGetMeshInfo)

	// Add the call_remote_tool tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "call_remote_tool",
		Description: "Call an MCP tool on a remote agent",
	}, node.handleCallRemoteTool)

	// Add the connect_peer tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "connect_peer",
		Description: "Connect to a peer in the mesh",
	}, node.handleConnectPeer)

	// Add the find_remote_tools tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "find_remote_tools",
		Description: "Discover MCP tools available on hosted services across the mesh. Returns name + description per tool. Optionally narrow by peer_id, service_name, or intent (intent is reserved for future ranking and is accepted-but-ignored).",
	}, node.handleFindRemoteTools)

	// Add the describe_remote_tool tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "describe_remote_tool",
		Description: "Return the description, input schema, and output schema for a specific aggregated tool on a specific peer. peer_id and tool_name are both required; tool_name must be a namespaced '<service>.<tool>' name as returned by find_remote_tools.",
	}, node.handleDescribeRemoteTool)

	// Create the SSE handler using the SDK
	sseHandler := mcp.NewSSEHandler(func(request *http.Request) *mcp.Server {
		return mcpServer
	}, nil)

	mux := http.NewServeMux()
	mux.Handle("/mcp/events", sseHandler)
	mux.Handle("/mcp/message", sseHandler)

	// Wrap in logging middleware to debug incoming requests
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debugf("MCP Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		mux.ServeHTTP(w, r)
	})

	return wrappedHandler
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
			logger.Debugf("[MCP] Failed to close stream: %v", err)
		}
	}()

	// Load this node's biscuit
	biscuitBytes, err := n.Store.LoadIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed to load identity biscuit: %w", err)
	}

	// Marshal AuthFrame
	authFrame := api.AuthFrame{
		Biscuit: biscuitBytes,
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

	// We don't need to marshall the params, the SDK takes care of it
	// Passing pre-marshaled []byte triggers encoding/json's base64 which gets rejected
	callParams := &mcp.CallToolParams{
		Name:      toolName,
		Arguments: params,
	}

	res, err := session.CallTool(ctx, callParams)
	if err != nil {
		return nil, fmt.Errorf("failed to call tool %s: %w", toolName, err)
	}

	return res, nil
}

// fetchRemoteServiceCatalog calls the remote peer's list_local_services
// MCP tool with the type filter and returns the parsed catalog.
func (n *SamNode) fetchRemoteServiceCatalog(ctx context.Context, peerID peer.ID, typeStr string) ([]*api.ServiceInfo, error) {
	res, err := n.callMCPToolOnce(ctx, peerID, "list_local_services", map[string]string{"type": typeStr})
	if err != nil {
		return nil, err
	}
	if res == nil || len(res.Content) == 0 {
		return nil, fmt.Errorf("empty response")
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return nil, fmt.Errorf("unexpected content type: %T", res.Content[0])
	}
	var services []*api.ServiceInfo
	if err := json.Unmarshal([]byte(text.Text), &services); err != nil {
		logger.Warnf("[Discovery] catalog unmarshal failed; raw text from %s: %q", peerID, text.Text)
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return services, nil
}
