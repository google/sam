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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/multiformats/go-multiaddr"
)

// SendMessageParams defines the parameters for the send_message tool.
type SendMessageParams struct {
	PeerID  string `json:"peer_id" jsonschema:"The Peer ID of the target agent"`
	Message string `json:"message" jsonschema:"The message content"`
}

// handleSendMessage implements the send_message tool.
func (n *SamNode) handleSendMessage(ctx context.Context, req *mcp.CallToolRequest, params SendMessageParams) (*mcp.CallToolResult, any, error) {
	response := fmt.Sprintf("Simulated sending message to %s: %s", params.PeerID, params.Message)

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: response},
		},
	}, nil, nil
}

// ListLocalServicesParams defines the parameters for the list_local_services tool.
type ListLocalServicesParams struct {
	Type string `json:"type,omitempty" jsonschema:"Optional service type filter (mcp, inference, a2a). Empty means all types."`
}

// handleListLocalServices implements the list_local_services tool.
func (n *SamNode) handleListLocalServices(ctx context.Context, req *mcp.CallToolRequest, params ListLocalServicesParams) (*mcp.CallToolResult, any, error) {
	typeFilter := api.ServiceType_SERVICE_TYPE_UNSPECIFIED
	if params.Type != "" {
		parsed, err := parseServiceType(params.Type)
		if err != nil {
			return nil, nil, err
		}
		typeFilter = parsed
	}
	services := n.ListLocalServices(typeFilter)
	logger.Infof("[ListLocalServices] Filter: %v, Returning %d services", typeFilter, len(services))
	respData, err := json.Marshal(services)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(respData)},
		},
	}, nil, nil
}

// DiscoverRemoteServicesParams defines the parameters for the discover_remote_services tool.
type DiscoverRemoteServicesParams struct {
	Type string `json:"type" jsonschema:"Service type (mcp, inference, a2a)"`
	Name string `json:"name,omitempty" jsonschema:"Optional service name. Omit to list all services of the given type."`
}

// handleDiscoverRemoteServices implements the discover_remote_services tool.
func (n *SamNode) handleDiscoverRemoteServices(ctx context.Context, req *mcp.CallToolRequest, params DiscoverRemoteServicesParams) (*mcp.CallToolResult, any, error) {
	serviceType, err := parseServiceType(params.Type)
	if err != nil || serviceType == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
		return nil, nil, fmt.Errorf("invalid or unspecified service type: %s", params.Type)
	}
	providers, err := n.DiscoverRemoteServices(ctx, serviceType, params.Name)
	if err != nil {
		return nil, nil, err
	}
	respData, err := json.Marshal(providers)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(respData)},
		},
	}, nil, nil
}

// MeshPubsubBroadcastParams defines the parameters for the mesh_pubsub_broadcast tool.
type MeshPubsubBroadcastParams struct {
	Topic   string `json:"topic" jsonschema:"GossipSub topic name"`
	Payload string `json:"payload" jsonschema:"Payload to publish"`
}

// handleMeshPubsubBroadcast implements the mesh_pubsub_broadcast tool.
func (n *SamNode) handleMeshPubsubBroadcast(ctx context.Context, req *mcp.CallToolRequest, params MeshPubsubBroadcastParams) (*mcp.CallToolResult, any, error) {
	n.mu.Lock()
	t, ok := n.topics[params.Topic]
	var err error
	if !ok {
		t, err = n.PubSub.Join(params.Topic)
		if err == nil {
			n.topics[params.Topic] = t
		}
	}
	n.mu.Unlock()
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
}

// PollMessagesParams defines the parameters for the poll_messages tool.
type PollMessagesParams struct {
	Topic string `json:"topic" jsonschema:"GossipSub topic name"`
}

// handlePollMessages implements the poll_messages tool.
func (n *SamNode) handlePollMessages(ctx context.Context, req *mcp.CallToolRequest, params PollMessagesParams) (*mcp.CallToolResult, any, error) {
	n.mu.Lock()
	msgs := n.receivedMsgs[params.Topic]
	delete(n.receivedMsgs, params.Topic) // Clear on read!
	n.mu.Unlock()

	response := fmt.Sprintf("Messages on topic %s: %v", params.Topic, msgs)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: response},
		},
	}, nil, nil
}

// SubscribeTopicParams defines the parameters for the subscribe_topic tool.
type SubscribeTopicParams struct {
	Topic string `json:"topic" jsonschema:"GossipSub topic name"`
}

// handleSubscribeTopic implements the subscribe_topic tool.
func (n *SamNode) handleSubscribeTopic(ctx context.Context, req *mcp.CallToolRequest, params SubscribeTopicParams) (*mcp.CallToolResult, any, error) {
	if err := n.subscribeToTopic(ctx, params.Topic); err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "Subscribed"},
		},
	}, nil, nil
}

// GetMeshInfoParams defines the parameters for the get_mesh_info tool.
type GetMeshInfoParams struct{}

// handleGetMeshInfo implements the get_mesh_info tool.
func (n *SamNode) handleGetMeshInfo(ctx context.Context, req *mcp.CallToolRequest, params GetMeshInfoParams) (*mcp.CallToolResult, any, error) {
	if n == nil {
		return nil, nil, fmt.Errorf("node not initialized")
	}

	peers := n.Host.Network().Peers()
	var connectedPeers []string
	for _, p := range peers {
		connectedPeers = append(connectedPeers, p.String())
	}
	dhtSize := n.DHT.RoutingTable().Size()

	resData := map[string]any{
		"connected_peers": connectedPeers,
		"dht_size":        dhtSize,
		"hub_peer_id":     n.HubPeerID.String(),
	}
	responseBytes, err := json.Marshal(resData)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(responseBytes)},
		},
	}, nil, nil
}

// CallRemoteToolParams defines the parameters for the call_remote_tool tool.
//
// Arguments is a JSON object whose shape matches the target server's
// input_schema (use describe_remote_tool to fetch it). Earlier revisions
// took a stringified JSON blob here; that footgun is gone.
type CallRemoteToolParams struct {
	PeerID    string         `json:"peer_id" jsonschema:"The Peer ID of the target agent"`
	ToolName  string         `json:"tool_name" jsonschema:"The name of the server to call"`
	Arguments map[string]any `json:"arguments,omitempty" jsonschema:"Server arguments as a JSON object whose keys match the target server's input_schema. Call describe_remote_tool first to learn the schema."`
}

// handleCallRemoteTool implements the call_remote_tool tool.
func (n *SamNode) handleCallRemoteTool(ctx context.Context, req *mcp.CallToolRequest, params CallRemoteToolParams) (*mcp.CallToolResult, any, error) {
	logger.Infof("[MCP] call_remote_tool called for peer %s, tool %s", params.PeerID, params.ToolName)
	targetPeer, err := peer.Decode(params.PeerID)
	if err != nil {
		return nil, nil, err
	}
	res, err := n.CallMCPTool(ctx, targetPeer, params.ToolName, params.Arguments)
	if err != nil {
		return nil, nil, err
	}
	return res, nil, nil
}

// ConnectPeerParams defines the parameters for the connect_peer tool.
type ConnectPeerParams struct {
	PeerAddr string `json:"peer_addr" jsonschema:"The full multiaddress of the peer to connect to"`
}

// handleConnectPeer implements the connect_peer tool.
func (n *SamNode) handleConnectPeer(ctx context.Context, req *mcp.CallToolRequest, params ConnectPeerParams) (*mcp.CallToolResult, any, error) {
	ma, err := multiaddr.NewMultiaddr(params.PeerAddr)
	if err != nil {
		return nil, nil, err
	}
	addrInfo, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return nil, nil, err
	}
	if err := n.Host.Connect(ctx, *addrInfo); err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "Connected"},
		},
	}, nil, nil
}

// FindRemoteToolsParams defines the parameters for the
// find_remote_tools tool.
type FindRemoteToolsParams struct {
	Intent      string `json:"intent,omitempty" jsonschema:"Natural-language description of what the caller is looking for. Reserved for future semantic ranking; currently accepted but ignored."`
	PeerID      string `json:"peer_id,omitempty" jsonschema:"Restrict the search to a single peer. Empty means search the whole mesh."`
	ServiceName string `json:"service_name,omitempty" jsonschema:"Restrict results to tools whose name starts with this service prefix (e.g. 'code-reviewer'). Empty means no service filter."`
	Cursor      string `json:"cursor,omitempty" jsonschema:"Optional pagination cursor. Pass the nextCursor from a previous response to get the next page."`
}

// remoteToolRow is one entry in the find_remote_tools response.
type remoteToolRow struct {
	PeerID      string `json:"peer_id"`
	ToolName    string `json:"tool_name"`
	Description string `json:"description"`
}

// handleFindRemoteTools implements the find_remote_tools tool.
//
// Scope:
//   - If params.PeerID is set, only that peer is queried.
//   - Otherwise the candidate list is obtained via DiscoverRemoteServices.
//
// Filtering:
//   - Tools without a "." in their name (infra tools) are excluded.
//   - If params.ServiceName is set, only tools whose name starts with
//     "<service_name>." are returned.
//   - params.Intent is accepted and logged at debug level, but does not
//     filter or rank results in this implementation (placeholder for
//     future semantic search).
func (n *SamNode) handleFindRemoteTools(ctx context.Context, req *mcp.CallToolRequest, params FindRemoteToolsParams) (*mcp.CallToolResult, any, error) {
	if params.Intent != "" {
		logger.Debugf("[find_remote_tools] intent (ignored): %q", params.Intent)
	}

	selfID := n.Host.ID().String()
	if params.PeerID != "" && params.PeerID == selfID {
		return nil, nil, fmt.Errorf("peer_id %q is this node; cross-mesh discovery cannot target self", params.PeerID)
	}

	var rows []remoteToolRow

	if params.PeerID != "" {
		pid, err := peer.Decode(params.PeerID)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid peer_id %q: %w", params.PeerID, err)
		}
		tools, err := n.fetchRemoteToolCatalogue(ctx, pid)
		if err != nil {
			return nil, nil, err
		}
		rows = appendFilteredRows(rows, params.PeerID, tools, params.ServiceName)
	} else {
		providers, err := n.DiscoverRemoteServices(ctx, api.ServiceType_SERVICE_TYPE_MCP, "")
		if err != nil {
			return nil, nil, fmt.Errorf("discover providers: %w", err)
		}
		seen := map[string]bool{}
		var peerIDs []peer.ID
		for _, p := range providers {
			if p.PeerId == selfID || seen[p.PeerId] {
				continue
			}
			seen[p.PeerId] = true
			pid, err := peer.Decode(p.PeerId)
			if err != nil {
				continue
			}
			peerIDs = append(peerIDs, pid)
		}

		rows = n.fanOutFetch(ctx, peerIDs, params.ServiceName)
	}

	if rows == nil {
		rows = []remoteToolRow{}
	}

	paginatedRows, nextCursor, err := PaginateSlice(rows, params.Cursor, 50)
	if err != nil {
		return nil, nil, err
	}

	respObj := map[string]any{
		"items": paginatedRows,
	}
	if nextCursor != "" {
		respObj["nextCursor"] = nextCursor
	}

	respData, err := json.Marshal(respObj)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(respData)}},
	}, nil, nil
}

// fetchRemoteToolCatalogue gets the remote node's service catalogue,
// then opens a separate libp2p stream to each MCP service to fetch its tools.
func (n *SamNode) fetchRemoteToolCatalogue(ctx context.Context, targetPeer peer.ID) ([]*mcp.Tool, error) {
	services, err := n.fetchRemoteServiceCatalog(ctx, targetPeer, "MCP")
	if err != nil {
		return nil, fmt.Errorf("fetch remote service catalog: %w", err)
	}

	var allTools []*mcp.Tool

	for _, svc := range services {
		if svc.Type != api.ServiceType_SERVICE_TYPE_MCP {
			continue
		}

		n.preparePeerAddrs(ctx, targetPeer)
		session, cleanup, err := n.ConnectMCPSession(ctx, targetPeer, svc.Name)
		if err != nil {
			logger.Debugf("Failed to connect MCP session for service %s: %v", svc.Name, err)
			continue
		}

		listRes, err := session.ListTools(ctx, nil)
		if err == nil {
			for _, t := range listRes.Tools {
				t.Name = svc.Name + "." + t.Name
				allTools = append(allTools, t)
			}
		}

		cleanup()
	}

	return allTools, nil
}

// appendFilteredRows appends rows for tools that have a namespaced name
// (containing ".") and, if serviceName is non-empty, whose name starts
// with "<serviceName>.".
func appendFilteredRows(rows []remoteToolRow, peerID string, tools []*mcp.Tool, serviceName string) []remoteToolRow {
	for _, tool := range tools {
		if !strings.Contains(tool.Name, ".") {
			continue
		}
		if serviceName != "" && !strings.HasPrefix(tool.Name, serviceName+".") {
			continue
		}
		rows = append(rows, remoteToolRow{
			PeerID:      peerID,
			ToolName:    tool.Name,
			Description: tool.Description,
		})
	}
	return rows
}

// fanOutFetch queries each peer's tool catalogue concurrently with a
// small cap and returns the filtered rows. Per-peer failures are
// logged at debug level and skipped — best-effort mesh-wide fetch.
func (n *SamNode) fanOutFetch(ctx context.Context, peers []peer.ID, serviceName string) []remoteToolRow {
	const maxConcurrent = 8
	sem := make(chan struct{}, maxConcurrent)

	var (
		mu   sync.Mutex
		rows []remoteToolRow
	)

	var wg sync.WaitGroup
	for _, pid := range peers {
		pid := pid
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			peerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			tools, err := n.fetchRemoteToolCatalogue(peerCtx, pid)
			if err != nil {
				logger.Debugf("[find_remote_tools] peer %s skipped: %v", pid, err)
				return
			}

			mu.Lock()
			rows = appendFilteredRows(rows, pid.String(), tools, serviceName)
			mu.Unlock()
		}()
	}
	wg.Wait()

	return rows
}

// remoteToolDescription is the JSON payload describe_local_tool emits on the
// peer side and describe_remote_tool re-emits on the caller side. The
// caller-side handler fills PeerID; the peer-side handler leaves it empty.
//
// InputSchema and OutputSchema mirror mcp.Tool's typing (`any`): the SDK
// surfaces them as map[string]any on the client side, and we re-marshal
// them verbatim without imposing a typed-schema constraint.
type remoteToolDescription struct {
	PeerID       string `json:"peer_id,omitempty"`
	ToolName     string `json:"tool_name"`
	Description  string `json:"description"`
	InputSchema  any    `json:"input_schema,omitempty"`
	OutputSchema any    `json:"output_schema,omitempty"`
}

// DescribeRemoteToolParams defines parameters for the describe_remote_tool
// sidecar tool.
type DescribeRemoteToolParams struct {
	PeerID   string `json:"peer_id" jsonschema:"Peer ID of the node hosting the server. Required."`
	ToolName string `json:"tool_name" jsonschema:"Namespaced server name as returned by find_remote_tools (e.g. 'code-reviewer.review_pr'). Required."`
}

// handleDescribeRemoteTool implements the describe_remote_tool client-facing tool.
func (n *SamNode) handleDescribeRemoteTool(ctx context.Context, req *mcp.CallToolRequest, params DescribeRemoteToolParams) (*mcp.CallToolResult, any, error) {
	if params.PeerID == "" {
		return nil, nil, fmt.Errorf("peer_id is required")
	}
	if params.ToolName == "" {
		return nil, nil, fmt.Errorf("tool_name is required")
	}

	pid, err := peer.Decode(params.PeerID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid peer_id: %w", err)
	}

	parts := strings.SplitN(params.ToolName, ".", 2)
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("invalid tool_name format, expected 'service.tool'")
	}
	serviceName := parts[0]
	actualToolName := parts[1]
	n.preparePeerAddrs(ctx, pid)

	session, cleanup, err := n.ConnectMCPSession(ctx, pid, serviceName)
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()

	listRes, err := session.ListTools(ctx, nil)
	if err != nil {
		return nil, nil, err
	}

	for _, t := range listRes.Tools {
		if t.Name == actualToolName {
			payload := remoteToolDescription{
				PeerID:       pid.String(),
				ToolName:     params.ToolName,
				Description:  t.Description,
				InputSchema:  t.InputSchema,
				OutputSchema: t.OutputSchema,
			}
			data, err := json.Marshal(payload)
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
			}, nil, nil
		}
	}

	return nil, nil, fmt.Errorf("tool not found on peer")
}

// CheckConnectivityParams defines the parameters for the check_connectivity tool.
type CheckConnectivityParams struct {
	PeerID string `json:"peer_id,omitempty" jsonschema:"Optional peer ID to ping."`
}

// handleCheckConnectivity implements the check_connectivity tool.
func (n *SamNode) handleCheckConnectivity(ctx context.Context, req *mcp.CallToolRequest, params CheckConnectivityParams) (*mcp.CallToolResult, any, error) {
	stats := map[string]any{
		"connected_peers":   len(n.Host.Network().Peers()),
		"total_known_peers": len(n.Host.Peerstore().Peers()),
	}

	if params.PeerID != "" {
		pid, err := peer.Decode(params.PeerID)
		if err == nil {
			n.preparePeerAddrs(ctx, pid)
			start := time.Now()
			err := n.Host.Connect(ctx, peer.AddrInfo{ID: pid})
			stats["ping_latency_ms"] = time.Since(start).Milliseconds()
			stats["ping_error"] = err != nil
			if err != nil {
				stats["ping_error_msg"] = err.Error()
			}
		} else {
			stats["ping_error"] = true
			stats["ping_error_msg"] = "invalid peer id"
		}
	} else if n.HubPeerID != "" {
		start := time.Now()
		err := n.Host.Connect(ctx, peer.AddrInfo{ID: n.HubPeerID})
		stats["hub_latency_ms"] = time.Since(start).Milliseconds()
		stats["hub_error"] = err != nil
		if err != nil {
			stats["hub_error_msg"] = err.Error()
		}
	}

	data, err := json.Marshal(stats)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

// GetTokenInfoParams defines parameters for the get_token_info tool.
type GetTokenInfoParams struct{}

// handleGetTokenInfo implements the get_token_info tool.
func (n *SamNode) handleGetTokenInfo(ctx context.Context, req *mcp.CallToolRequest, params GetTokenInfoParams) (*mcp.CallToolResult, any, error) {
	info := map[string]any{
		"has_token": false,
	}

	token, err := n.Store.LoadIdentity()
	if err == nil && len(token) > 0 {
		info["has_token"] = true
		exp, err := n.Store.LoadIdentityExpiration()
		if err == nil {
			info["expires_in_seconds"] = time.Until(time.Unix(exp, 0)).Seconds()
			info["is_expired"] = time.Now().Unix() > exp
		}
	}

	data, err := json.Marshal(info)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

// GetNetworkInfoParams defines parameters for the get_network_info tool.
type GetNetworkInfoParams struct{}

// handleGetNetworkInfo implements the get_network_info tool.
func (n *SamNode) handleGetNetworkInfo(ctx context.Context, req *mcp.CallToolRequest, params GetNetworkInfoParams) (*mcp.CallToolResult, any, error) {
	listenAddrs := []string{}
	for _, a := range n.Host.Network().ListenAddresses() {
		listenAddrs = append(listenAddrs, a.String())
	}

	observedAddrs := []string{}
	for _, a := range n.Host.Addrs() {
		observedAddrs = append(observedAddrs, a.String())
	}

	info := map[string]any{
		"listen_addresses":   listenAddrs,
		"observed_addresses": observedAddrs,
	}
	data, err := json.Marshal(info)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

// GetRecentLogsParams defines parameters for the get_recent_logs tool.
type GetRecentLogsParams struct{}

// handleGetRecentLogs implements the get_recent_logs tool.
func (n *SamNode) handleGetRecentLogs(ctx context.Context, req *mcp.CallToolRequest, params GetRecentLogsParams) (*mcp.CallToolResult, any, error) {
	logs := GetRecentLogs()
	data, err := json.Marshal(map[string]any{"logs": logs})
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

// FindRemoteResourcesParams defines the parameters for find_remote_resources.
type FindRemoteResourcesParams struct {
	PeerID      string `json:"peer_id,omitempty" jsonschema:"Restrict the search to a single peer. Empty means search the whole mesh."`
	ServiceName string `json:"service_name,omitempty" jsonschema:"Restrict results to resources whose name starts with this service prefix."`
	Cursor      string `json:"cursor,omitempty" jsonschema:"Optional pagination cursor."`
}

// remoteResourceRow is one entry in the find_remote_resources response.
type remoteResourceRow struct {
	PeerID      string `json:"peer_id"`
	ResourceURI string `json:"resource_uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (n *SamNode) handleFindRemoteResources(ctx context.Context, req *mcp.CallToolRequest, params FindRemoteResourcesParams) (*mcp.CallToolResult, any, error) {
	selfID := n.Host.ID().String()
	if params.PeerID != "" && params.PeerID == selfID {
		return nil, nil, fmt.Errorf("peer_id %q is this node; cross-mesh discovery cannot target self", params.PeerID)
	}

	var rows []remoteResourceRow

	if params.PeerID != "" {
		pid, err := peer.Decode(params.PeerID)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid peer_id %q: %w", params.PeerID, err)
		}
		resources, err := n.fetchRemoteResourceCatalogue(ctx, pid)
		if err != nil {
			return nil, nil, err
		}
		rows = appendFilteredResourceRows(rows, params.PeerID, resources, params.ServiceName)
	} else {
		providers, err := n.DiscoverRemoteServices(ctx, api.ServiceType_SERVICE_TYPE_MCP, "")
		if err != nil {
			return nil, nil, fmt.Errorf("discover providers: %w", err)
		}
		seen := map[string]bool{}
		var peerIDs []peer.ID
		for _, p := range providers {
			if p.PeerId == selfID || seen[p.PeerId] {
				continue
			}
			seen[p.PeerId] = true
			pid, err := peer.Decode(p.PeerId)
			if err != nil {
				continue
			}
			peerIDs = append(peerIDs, pid)
		}

		rows = n.fanOutFetchResources(ctx, peerIDs, params.ServiceName)
	}

	if rows == nil {
		rows = []remoteResourceRow{}
	}

	paginatedRows, nextCursor, err := PaginateSlice(rows, params.Cursor, 50)
	if err != nil {
		return nil, nil, err
	}

	respObj := map[string]any{
		"items": paginatedRows,
	}
	if nextCursor != "" {
		respObj["nextCursor"] = nextCursor
	}

	respData, err := json.Marshal(respObj)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(respData)}},
	}, nil, nil
}

func (n *SamNode) fetchRemoteResourceCatalogue(ctx context.Context, targetPeer peer.ID) ([]*mcp.Resource, error) {
	services, err := n.fetchRemoteServiceCatalog(ctx, targetPeer, "MCP")
	if err != nil {
		return nil, fmt.Errorf("fetch remote service catalog: %w", err)
	}

	var allResources []*mcp.Resource

	for _, svc := range services {
		if svc.Type != api.ServiceType_SERVICE_TYPE_MCP {
			continue
		}

		n.preparePeerAddrs(ctx, targetPeer)
		session, cleanup, err := n.ConnectMCPSession(ctx, targetPeer, svc.Name)
		if err != nil {
			continue
		}

		listRes, err := session.ListResources(ctx, &mcp.ListResourcesParams{})
		if err == nil && listRes != nil {
			for _, r := range listRes.Resources {
				// Namespace the URI scheme or name if we want, but resources are URIs.
				// We'll prefix the Name to indicate origin.
				r.Name = svc.Name + "." + r.Name
				allResources = append(allResources, r)
			}
		}
		cleanup()
	}

	return allResources, nil
}

func appendFilteredResourceRows(rows []remoteResourceRow, peerID string, resources []*mcp.Resource, serviceName string) []remoteResourceRow {
	for _, r := range resources {
		if serviceName != "" && !strings.HasPrefix(r.Name, serviceName+".") {
			continue
		}
		rows = append(rows, remoteResourceRow{
			PeerID:      peerID,
			ResourceURI: r.URI,
			Name:        r.Name,
			Description: r.Description,
		})
	}
	return rows
}

func (n *SamNode) fanOutFetchResources(ctx context.Context, peers []peer.ID, serviceName string) []remoteResourceRow {
	const maxConcurrent = 8
	sem := make(chan struct{}, maxConcurrent)

	var (
		mu   sync.Mutex
		rows []remoteResourceRow
	)

	var wg sync.WaitGroup
	for _, pid := range peers {
		pid := pid
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			peerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			resources, err := n.fetchRemoteResourceCatalogue(peerCtx, pid)
			if err != nil {
				return
			}
			mu.Lock()
			rows = appendFilteredResourceRows(rows, pid.String(), resources, serviceName)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return rows
}

// ReadRemoteResourceParams defines the parameters for read_remote_resource.
type ReadRemoteResourceParams struct {
	PeerID string `json:"peer_id" jsonschema:"The Peer ID of the target agent"`
	URI    string `json:"uri" jsonschema:"The URI of the remote resource"`
}

func (n *SamNode) handleReadRemoteResource(ctx context.Context, req *mcp.CallToolRequest, params ReadRemoteResourceParams) (*mcp.CallToolResult, any, error) {
	targetPeer, err := peer.Decode(params.PeerID)
	if err != nil {
		return nil, nil, err
	}

	// Try all MCP services on the remote peer to see which one has the resource
	services, err := n.fetchRemoteServiceCatalog(ctx, targetPeer, "MCP")
	if err != nil {
		return nil, nil, err
	}

	for _, svc := range services {
		if svc.Type != api.ServiceType_SERVICE_TYPE_MCP {
			continue
		}

		session, cleanup, err := n.ConnectMCPSession(ctx, targetPeer, svc.Name)
		if err != nil {
			continue
		}

		res, err := session.ReadResource(ctx, &mcp.ReadResourceParams{
			URI: params.URI,
		})

		if err == nil && res != nil && len(res.Contents) > 0 {
			defer cleanup()

			// Marshal the contents
			data, _ := json.Marshal(res.Contents)
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: string(data)},
				},
			}, nil, nil
		}
		cleanup()
	}

	return nil, nil, fmt.Errorf("resource %s not found on peer %s", params.URI, params.PeerID)
}

// FindRemotePromptsParams defines the parameters for find_remote_prompts.
type FindRemotePromptsParams struct {
	PeerID      string `json:"peer_id,omitempty" jsonschema:"Restrict the search to a single peer. Empty means search the whole mesh."`
	ServiceName string `json:"service_name,omitempty" jsonschema:"Restrict results to prompts whose name starts with this service prefix."`
	Cursor      string `json:"cursor,omitempty" jsonschema:"Optional pagination cursor."`
}

// remotePromptRow is one entry in the find_remote_prompts response.
type remotePromptRow struct {
	PeerID      string                `json:"peer_id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Arguments   []*mcp.PromptArgument `json:"arguments"`
}

func (n *SamNode) handleFindRemotePrompts(ctx context.Context, req *mcp.CallToolRequest, params FindRemotePromptsParams) (*mcp.CallToolResult, any, error) {
	selfID := n.Host.ID().String()
	if params.PeerID != "" && params.PeerID == selfID {
		return nil, nil, fmt.Errorf("peer_id %q is this node; cross-mesh discovery cannot target self", params.PeerID)
	}

	var rows []remotePromptRow

	if params.PeerID != "" {
		pid, err := peer.Decode(params.PeerID)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid peer_id %q: %w", params.PeerID, err)
		}
		prompts, err := n.fetchRemotePromptCatalogue(ctx, pid)
		if err != nil {
			return nil, nil, err
		}
		rows = appendFilteredPromptRows(rows, params.PeerID, prompts, params.ServiceName)
	} else {
		providers, err := n.DiscoverRemoteServices(ctx, api.ServiceType_SERVICE_TYPE_MCP, "")
		if err != nil {
			return nil, nil, fmt.Errorf("discover providers: %w", err)
		}
		seen := map[string]bool{}
		var peerIDs []peer.ID
		for _, p := range providers {
			if p.PeerId == selfID || seen[p.PeerId] {
				continue
			}
			seen[p.PeerId] = true
			pid, err := peer.Decode(p.PeerId)
			if err != nil {
				continue
			}
			peerIDs = append(peerIDs, pid)
		}

		rows = n.fanOutFetchPrompts(ctx, peerIDs, params.ServiceName)
	}

	if rows == nil {
		rows = []remotePromptRow{}
	}

	paginatedRows, nextCursor, err := PaginateSlice(rows, params.Cursor, 50)
	if err != nil {
		return nil, nil, err
	}

	respObj := map[string]any{
		"items": paginatedRows,
	}
	if nextCursor != "" {
		respObj["nextCursor"] = nextCursor
	}

	respData, err := json.Marshal(respObj)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(respData)}},
	}, nil, nil
}

func (n *SamNode) fetchRemotePromptCatalogue(ctx context.Context, targetPeer peer.ID) ([]*mcp.Prompt, error) {
	services, err := n.fetchRemoteServiceCatalog(ctx, targetPeer, "MCP")
	if err != nil {
		return nil, fmt.Errorf("fetch remote service catalog: %w", err)
	}

	var allPrompts []*mcp.Prompt

	for _, svc := range services {
		if svc.Type != api.ServiceType_SERVICE_TYPE_MCP {
			continue
		}

		n.preparePeerAddrs(ctx, targetPeer)
		session, cleanup, err := n.ConnectMCPSession(ctx, targetPeer, svc.Name)
		if err != nil {
			continue
		}

		listRes, err := session.ListPrompts(ctx, &mcp.ListPromptsParams{})
		if err == nil && listRes != nil {
			for _, p := range listRes.Prompts {
				p.Name = svc.Name + "." + p.Name
				allPrompts = append(allPrompts, p)
			}
		}
		cleanup()
	}

	return allPrompts, nil
}

func appendFilteredPromptRows(rows []remotePromptRow, peerID string, prompts []*mcp.Prompt, serviceName string) []remotePromptRow {
	for _, p := range prompts {
		if serviceName != "" && !strings.HasPrefix(p.Name, serviceName+".") {
			continue
		}
		rows = append(rows, remotePromptRow{
			PeerID:      peerID,
			Name:        p.Name,
			Description: p.Description,
			Arguments:   p.Arguments,
		})
	}
	return rows
}

func (n *SamNode) fanOutFetchPrompts(ctx context.Context, peers []peer.ID, serviceName string) []remotePromptRow {
	const maxConcurrent = 8
	sem := make(chan struct{}, maxConcurrent)

	var (
		mu   sync.Mutex
		rows []remotePromptRow
	)

	var wg sync.WaitGroup
	for _, pid := range peers {
		pid := pid
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			peerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			prompts, err := n.fetchRemotePromptCatalogue(peerCtx, pid)
			if err != nil {
				return
			}
			mu.Lock()
			rows = appendFilteredPromptRows(rows, pid.String(), prompts, serviceName)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return rows
}

// GetRemotePromptParams defines the parameters for get_remote_prompt.
type GetRemotePromptParams struct {
	PeerID    string            `json:"peer_id" jsonschema:"The Peer ID of the target agent"`
	Name      string            `json:"name" jsonschema:"The namespaced name of the remote prompt (e.g. 'service.prompt')"`
	Arguments map[string]string `json:"arguments,omitempty" jsonschema:"Arguments to pass to the prompt"`
}

func (n *SamNode) handleGetRemotePrompt(ctx context.Context, req *mcp.CallToolRequest, params GetRemotePromptParams) (*mcp.CallToolResult, any, error) {
	targetPeer, err := peer.Decode(params.PeerID)
	if err != nil {
		return nil, nil, err
	}

	targetService := api.CatalogTarget
	originalPromptName := params.Name
	if parts := strings.SplitN(params.Name, ".", 2); len(parts) == 2 {
		targetService = parts[0]
		originalPromptName = parts[1]
	}

	session, cleanup, err := n.ConnectMCPSession(ctx, targetPeer, targetService)
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()

	res, err := session.GetPrompt(ctx, &mcp.GetPromptParams{
		Name:      originalPromptName,
		Arguments: params.Arguments,
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to get prompt %s: %w", params.Name, err)
	}

	data, _ := json.Marshal(res)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(data)},
		},
	}, nil, nil
}

// PaginateSlice ...
func PaginateSlice[T any](items []T, cursor string, limit int) ([]T, string, error) {
	if limit <= 0 {
		limit = 50
	}
	startIdx := 0
	if cursor != "" {
		idx, err := strconv.Atoi(cursor)
		if err != nil || idx < 0 {
			return nil, "", fmt.Errorf("invalid cursor: %q", cursor)
		}
		startIdx = idx
	}
	if startIdx >= len(items) {
		return []T{}, "", nil
	}
	endIdx := startIdx + limit
	nextCursor := ""
	if endIdx < len(items) {
		nextCursor = strconv.Itoa(endIdx)
	} else {
		endIdx = len(items)
	}
	return items[startIdx:endIdx], nextCursor, nil
}
