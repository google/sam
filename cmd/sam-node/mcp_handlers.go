package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
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
// Arguments is a JSON object whose shape matches the target tool's
// input_schema (use describe_remote_tool to fetch it). Earlier revisions
// took a stringified JSON blob here; that footgun is gone.
type CallRemoteToolParams struct {
	PeerID    string         `json:"peer_id" jsonschema:"The Peer ID of the target agent"`
	ToolName  string         `json:"tool_name" jsonschema:"The name of the tool to call"`
	Arguments map[string]any `json:"arguments,omitempty" jsonschema:"Tool arguments as a JSON object whose keys match the target tool's input_schema. Call describe_remote_tool first to learn the schema."`
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
	respData, err := json.Marshal(rows)
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
	biscuitBytes, err := n.Store.LoadIdentity()
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}

	for _, svc := range services {
		if svc.Type != api.ServiceType_SERVICE_TYPE_MCP {
			continue
		}

		s, err := n.Host.NewStream(ctx, targetPeer, api.MCPProtocolID)
		if err != nil {
			logger.Debugf("Failed to open stream for service %s: %v", svc.Name, err)
			continue
		}

		authFrame := api.AuthFrame{Biscuit: biscuitBytes, TargetService: svc.Name}
		authBytes, _ := proto.Marshal(&authFrame)

		writer := msgio.NewVarintWriter(s)
		if err := writer.WriteMsg(authBytes); err != nil {
			_ = s.Close()
			continue
		}

		reader := msgio.NewVarintReaderSize(s, 1024*64)
		respMsg, err := reader.ReadMsg()
		if err != nil {
			_ = s.Close()
			continue
		}
		defer reader.ReleaseMsg(respMsg)

		var resp api.AuthResponse
		if err := proto.Unmarshal(respMsg, &resp); err != nil || !resp.Success {
			_ = s.Close()
			continue
		}

		transport := NewStreamTransport(s)
		client := mcp.NewClient(&mcp.Implementation{Name: "sam-node-find", Version: "0.1.0"}, nil)
		session, err := client.Connect(ctx, transport, nil)
		if err != nil {
			_ = s.Close()
			continue
		}

		listRes, err := session.ListTools(ctx, nil)
		if err == nil {
			for _, t := range listRes.Tools {
				t.Name = svc.Name + "." + t.Name
				allTools = append(allTools, t)
			}
		}

		_ = session.Close()
		_ = s.Close()
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
	PeerID   string `json:"peer_id" jsonschema:"Peer ID of the node hosting the tool. Required."`
	ToolName string `json:"tool_name" jsonschema:"Namespaced tool name as returned by find_remote_tools (e.g. 'code-reviewer.review_pr'). Required."`
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

	biscuitBytes, err := n.Store.LoadIdentity()
	if err != nil {
		return nil, nil, err
	}

	s, err := n.Host.NewStream(ctx, pid, api.MCPProtocolID)
	if err != nil {
		return nil, nil, fmt.Errorf("open stream: %w", err)
	}
	defer func() { _ = s.Close() }()

	authFrame := api.AuthFrame{Biscuit: biscuitBytes, TargetService: serviceName}
	authBytes, _ := proto.Marshal(&authFrame)

	writer := msgio.NewVarintWriter(s)
	if err := writer.WriteMsg(authBytes); err != nil {
		return nil, nil, err
	}

	reader := msgio.NewVarintReaderSize(s, 1024*64)
	respMsg, err := reader.ReadMsg()
	if err != nil {
		return nil, nil, err
	}
	defer reader.ReleaseMsg(respMsg)

	var authResp api.AuthResponse
	if err := proto.Unmarshal(respMsg, &authResp); err != nil || !authResp.Success {
		return nil, nil, fmt.Errorf("auth rejected")
	}

	transport := NewStreamTransport(s)
	client := mcp.NewClient(&mcp.Implementation{Name: "sam-node-describe", Version: "0.1.0"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = session.Close() }()

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
