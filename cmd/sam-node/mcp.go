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
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-msgio"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/multiformats/go-multiaddr"
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

	// Add the check_connectivity tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "check_connectivity",
		Description: "Diagnose the node's ability to communicate with the SAM hub and the broader mesh network.",
	}, node.handleCheckConnectivity)

	// Add the get_token_info tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_token_info",
		Description: "Inspects the local auth token, returns its expiration time and status.",
	}, node.handleGetTokenInfo)

	// Add the get_network_info tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_network_info",
		Description: "Returns local network interfaces and listener addresses.",
	}, node.handleGetNetworkInfo)

	// Add the get_recent_logs tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_recent_logs",
		Description: "Returns the last few lines of the node's log output.",
	}, node.handleGetRecentLogs)

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

	// Attempt to filter private IPs and resolve direct IPs for relay nodes.
	n.preparePeerAddrs(ctx, targetPeer)

	for i := 0; i < maxRetries; i++ {
		res, err = n.callMCPToolOnce(ctx, targetPeer, toolName, params)
		if err == nil {
			return res, nil
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "context deadline exceeded") {
			logger.Warnf("[MCP] Tool call failed with timeout or cancellation, not retrying: %v", err)
			return nil, err
		}
		logger.Warnf("[MCP] Tool call failed, retrying in %v: %v", backoff, err)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("context canceled during retry: %w", ctx.Err())
		case <-timer.C:
		}
		backoff *= 2
	}
	return nil, fmt.Errorf("failed after %d retries: %w", maxRetries, err)
}

func (n *SamNode) ConnectMCPSession(ctx context.Context, targetPeer peer.ID, targetService string) (*mcp.ClientSession, func(), error) {
	// Open stream
	logger.Debugf("Dialing %s for MCP...\n", targetPeer)
	// For discovery, we want a fast failure, but for tool calls, we can wait a bit. We'll use the context's deadline,
	// but bound it to 15s max for the dial itself to prevent hanging.
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	dialCtx = network.WithAllowLimitedConn(dialCtx, "mcp")
	defer cancel()

	s, err := n.Host.NewStream(dialCtx, targetPeer, api.MCPProtocolID)
	if err != nil {
		// If dial failed completely, mark private IP failed so we skip it next time
		if putErr := n.Host.Peerstore().Put(targetPeer, PeerstoreKeyPrivateIPFailed, true); putErr != nil {
			logger.Errorf("[Discovery] Failed to put peerstore private IP failed key: %v", putErr)
		}
		return nil, nil, fmt.Errorf("failed to open stream to %s: %w", targetPeer, err)
	}

	if remoteAddr := s.Conn().RemoteMultiaddr(); remoteAddr != nil {
		parts := multiaddr.Split(remoteAddr)
		isCircuit := len(parts) >= 2 && parts[len(parts)-1].Protocol().Code == multiaddr.P_CIRCUIT

		var putVal bool
		if isCircuit || !isPrivateIP(remoteAddr) {
			putVal = true
		} else {
			putVal = false
		}
		if putErr := n.Host.Peerstore().Put(targetPeer, PeerstoreKeyPrivateIPFailed, putVal); putErr != nil {
			logger.Errorf("[Discovery] Failed to put peerstore private IP failed key: %v", putErr)
		}
	}
	logger.Debugf("Opened stream to %s for MCP\n", targetPeer)

	cleanup := func() {
		if err := s.Close(); err != nil {
			logger.Debugf("[MCP] Failed to close stream: %v", err)
		}
	}

	// Load this node's biscuit
	biscuitBytes, err := n.Store.LoadIdentity()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to load identity biscuit: %w", err)
	}

	// Marshal AuthFrame
	authFrame := api.AuthFrame{
		Biscuit:       biscuitBytes,
		TargetService: targetService,
	}
	authBytes, _ := proto.Marshal(&authFrame)

	// Handshake should be fast; set a hard deadline to prevent hanging
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))

	// Write AuthFrame
	logger.Debugf("Writing auth frame to %s...\n", targetPeer)
	writer := msgio.NewVarintWriter(s)
	if err := writer.WriteMsg(authBytes); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to write auth frame to %s: %w", targetPeer, err)
	}

	// Read ACK
	logger.Debugf("Reading auth response from %s...\n", targetPeer)
	reader := msgio.NewVarintReaderSize(s, 1024*64)
	msg, err := reader.ReadMsg()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to read auth response from %s: %w", targetPeer, err)
	}
	defer reader.ReleaseMsg(msg)

	// Clear deadline so the MCP SDK can use the stream normally without timing out
	_ = s.SetDeadline(time.Time{})

	var resp api.AuthResponse
	if err := proto.Unmarshal(msg, &resp); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("invalid auth response from %s: %w", targetPeer, err)
	}

	if !resp.Success {
		cleanup()
		return nil, nil, fmt.Errorf("auth rejected by %s: %s", targetPeer, resp.Error)
	}

	// Handoff to SDK using custom transport
	transport := NewStreamTransport(s)
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "sam-node-mcp-client", Version: "0.1.0"}, nil)

	session, err := mcpClient.Connect(ctx, transport, nil)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to connect client: %w", err)
	}

	fullCleanup := func() {
		_ = session.Close()
		cleanup()
	}

	return session, fullCleanup, nil
}

func (n *SamNode) callMCPToolOnce(ctx context.Context, targetPeer peer.ID, toolName string, params any) (*mcp.CallToolResult, error) {
	targetService := "/sam/catalog"
	originalToolName := toolName
	if parts := strings.SplitN(toolName, ".", 2); len(parts) == 2 {
		targetService = parts[0]
		originalToolName = parts[1]
	}

	session, cleanup, err := n.ConnectMCPSession(ctx, targetPeer, targetService)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// We don't need to marshall the params, the SDK takes care of it
	// Passing pre-marshaled []byte triggers encoding/json's base64 which gets rejected
	callParams := &mcp.CallToolParams{
		Name:      originalToolName,
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
	n.preparePeerAddrs(ctx, peerID)

	session, cleanup, err := n.ConnectMCPSession(ctx, peerID, "/sam/catalog")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	callParams := &mcp.CallToolParams{
		Name:      "list_local_services",
		Arguments: map[string]string{"type": typeStr},
	}

	res, err := session.CallTool(ctx, callParams)
	if err != nil {
		return nil, fmt.Errorf("failed to call tool list_local_services: %w", err)
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

// preparePeerAddrs scans the target peer's addresses, filters out unroutable private IPs,
// and ensures relay circuits are available. This prevents dial backoff errors when the
// relay is behind a load-balanced DNS address or when pods advertise internal IPs.
func (n *SamNode) preparePeerAddrs(ctx context.Context, targetPeer peer.ID) {
	if n.Host == nil || n.DHT == nil {
		logger.Debugf("[Discovery] Host or DHT is nil")
		return
	}
	logger.Debugf("[Discovery] connectedness for %s: %s (conns: %d)", targetPeer, n.Host.Network().Connectedness(targetPeer), len(n.Host.Network().ConnsToPeer(targetPeer)))

	// If we are currently connected to the peer, examine active connections to see if any are direct private IPs.
	cond := n.Host.Network().Connectedness(targetPeer)
	if cond == network.Connected || cond == network.Limited {
		conns := n.Host.Network().ConnsToPeer(targetPeer)
		hasDirectPrivateIP := false
		for _, c := range conns {
			remoteAddr := c.RemoteMultiaddr()
			if isPrivateIP(remoteAddr) && !hasCircuit(remoteAddr) {
				hasDirectPrivateIP = true
				break
			}
		}
		if !hasDirectPrivateIP {
			if err := n.Host.Peerstore().Put(targetPeer, PeerstoreKeyPrivateIPFailed, true); err != nil {
				logger.Errorf("[Discovery] Failed to put peerstore private IP failed key: %v", err)
			}
			logger.Debugf("[Discovery] Peer %s is connected via relay, marking private IP as failed", targetPeer)
		} else {
			if err := n.Host.Peerstore().Put(targetPeer, PeerstoreKeyPrivateIPFailed, false); err != nil {
				logger.Errorf("[Discovery] Failed to put peerstore private IP failed key: %v", err)
			}
		}
	}

	changed := false
	addrs := n.Host.Peerstore().Addrs(targetPeer)
	if len(addrs) == 0 {
		logger.Debugf("[Discovery] No addresses in peerstore for %s, querying DHT...", targetPeer)
		findCtx, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
		addrInfo, err := n.DHT.FindPeer(findCtx, targetPeer)
		cancel()
		if err != nil {
			logger.Debugf("[Discovery] Failed to find peer %s on DHT: %v", targetPeer, err)
		} else {
			addrs = addrInfo.Addrs
			if len(addrs) > 0 {
				changed = true
			}
		}
	}
	logger.Debugf("[Discovery] preparePeerAddrs for %s: found %d addrs in peerstore", targetPeer, len(addrs))

	var validAddrs []multiaddr.Multiaddr
	seen := make(map[string]struct{})

	addUnique := func(ma multiaddr.Multiaddr) bool {
		str := ma.String()
		if _, ok := seen[str]; !ok {
			seen[str] = struct{}{}
			validAddrs = append(validAddrs, ma)
			return true
		}
		return false
	}

	for _, ma := range addrs {
		parts := multiaddr.Split(ma)

		// If it's a circuit relay, we always keep the generic /p2p-circuit form.
		// We'll reconstruct it below. But we must also check if the address itself is routable.
		isCircuit := len(parts) >= 2 && parts[len(parts)-1].Protocol().Code == multiaddr.P_CIRCUIT

		if !isCircuit {
			// Regular address (not a circuit relay). Filter private IPs if loopback isn't allowed,
			// and we know from a previous dial that private IPs are unreachable for this peer.
			if isPrivateIP(ma) && !n.AllowLoopback {
				val, err := n.Host.Peerstore().Get(targetPeer, PeerstoreKeyPrivateIPFailed)
				if failed, ok := val.(bool); err == nil && ok && failed {
					changed = true
					logger.Debugf("[Discovery] Skipping private IP %s for %s due to previous failure", ma, targetPeer)
					continue
				}
			}
			addUnique(ma)
			continue
		}

		// Keep the advertised circuit address
		addUnique(ma)

		// Also synthesize a generic /p2p-circuit using the relay's peer ID.
		p2pPart := parts[len(parts)-2]
		if p2pPart.Protocol().Code != multiaddr.P_P2P {
			continue
		}

		relayID, err := peer.Decode(p2pPart.Value())
		if err != nil {
			continue
		}

		if len(n.Host.Peerstore().Addrs(relayID)) == 0 {
			logger.Debugf("[Discovery] No addresses for relay %s, resolving via DHT...", relayID)
			findCtx, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
			addrInfo, err := n.DHT.FindPeer(findCtx, relayID)
			cancel()
			if err != nil {
				logger.Debugf("[Discovery] Failed to find relay %s on DHT: %v", relayID, err)
			} else {
				n.Host.Peerstore().AddAddrs(relayID, addrInfo.Addrs, peerstore.TempAddrTTL)
			}
		}

		circuitAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/p2p/%s/p2p-circuit", relayID.String()))
		if err == nil {
			if addUnique(circuitAddr) {
				changed = true
			}
		}
	}

	if changed && len(validAddrs) > 0 {
		// Clear existing addresses to prevent libp2p from hanging on dead private IPs
		n.Host.Peerstore().ClearAddrs(targetPeer)
		n.Host.Peerstore().AddAddrs(targetPeer, validAddrs, peerstore.TempAddrTTL)
		logger.Debugf("[Discovery] Replaced addrs for %s with %d routable/circuit addrs", targetPeer, len(validAddrs))
	}
}
