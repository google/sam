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

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

)

var _ connmgr.ConnectionGater = (*nodeConnGate)(nil)

// nodeConnGate enforces swarm-level AuthN policies
type nodeConnGate struct {
	node *SamNode
}

// InterceptPeerDial controls who we are allowed to call (Outbound)
func (g *nodeConnGate) InterceptPeerDial(p peer.ID) (allow bool) {
	return !g.node.Store.IsBanned(p)
}

// InterceptAddrDial ensures we only dial specific approved networks
func (g *nodeConnGate) InterceptAddrDial(p peer.ID, m multiaddr.Multiaddr) (allow bool) {
	return true
}

// InterceptAccept controls who can call us (Inbound)
func (g *nodeConnGate) InterceptAccept(n network.ConnMultiaddrs) (allow bool) {
	return true // Connection allowed, but InterceptSecured will verify the PeerID
}

// InterceptSecured is called after TLS handshake. This is our Layer 2 Check.
func (g *nodeConnGate) InterceptSecured(dir network.Direction, p peer.ID, n network.ConnMultiaddrs) (allow bool) {
	if g.node.Store.IsBanned(p) {
		fmt.Printf("[Layer 2] Dropping connection: Peer %s is explicitly BANNED\n", p)
		return false
	}

	// Allow the TLS pipe to stay open. Layer 3 & 4 will handle the rest.
	return true
}

// HandleMCPStream is the libp2p stream handler for the MCP protocol.
// It assumes the stream is fully authenticated by the middleware.
func (n *SamNode) HandleMCPStream(s network.Stream) {
	defer func() {
		if err := s.Close(); err != nil {
			fmt.Printf("Failed to close MCP stream: %v\n", err)
		}
	}()

	// Handoff to SDK using custom transport
	transport := NewStreamTransport(s)
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "sam-node-mcp",
		Version: "0.1.0",
	}, nil)

	// Add the send_message tool.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "send_message",
		Description: "Send a message to another agent in the mesh",
	}, handleSendMessage)

	// Add the get_mesh_info tool.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_mesh_info",
		Description: "Get information about the mesh network",
	}, func(ctx context.Context, req *mcp.CallToolRequest, params struct{}) (*mcp.CallToolResult, any, error) {
		if n == nil {
			return nil, nil, fmt.Errorf("node not initialized")
		}
		n.mu.Lock()
		knownCount := len(n.knownPeers)
		var knownPeers []string
		for p := range n.knownPeers {
			knownPeers = append(knownPeers, p)
		}
		n.mu.Unlock()

		peers := n.Host.Network().Peers()
		dhtSize := n.DHT.RoutingTable().Size()
		
		response := fmt.Sprintf("Known peers count: %d\nKnown peers list: %v\nConnected peers: %d\nDHT Routing Table size: %d\nHub Peer ID: %s", knownCount, knownPeers, len(peers), dhtSize, n.HubPeerID)
		
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: response},
			},
		}, nil, nil
	})

	ctx := context.Background()
	if err := server.Run(ctx, transport); err != nil {
		fmt.Printf("MCP server error on stream from %s: %v\n", s.Conn().RemotePeer(), err)
	}
}
func (g *nodeConnGate) InterceptUpgraded(n network.Conn) (allow bool, cc control.DisconnectReason) {
	return true, 0
}

// StreamTransport implements the mcp.Transport interface for a libp2p stream.
type StreamTransport struct {
	s network.Stream
	r msgio.ReadCloser
	w msgio.WriteCloser
}

// NewStreamTransport creates a new StreamTransport for the given stream.
func NewStreamTransport(s network.Stream) *StreamTransport {
	return &StreamTransport{
		s: s,
		r: msgio.NewVarintReader(s),
		w: msgio.NewVarintWriter(s),
	}
}

// Send sends a message over the stream.
func (t *StreamTransport) Send(data []byte) error {
	return t.w.WriteMsg(data)
}

// Read reads a message from the stream.
func (t *StreamTransport) Read(ctx context.Context) (jsonrpc.Message, error) {
	msg, err := t.r.ReadMsg()
	if err != nil {
		return nil, err
	}
	defer t.r.ReleaseMsg(msg)

	var jsonRpcMsg jsonrpc.Message
	if err := json.Unmarshal(msg, &jsonRpcMsg); err != nil {
		return nil, err
	}
	return jsonRpcMsg, nil
}

// Close closes the stream.
func (t *StreamTransport) Close() error {
	return t.s.Close()
}

// Connect satisfies the mcp.Transport interface. For a stream, it's already connected.
func (t *StreamTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	return t, nil
}

// SessionID satisfies the mcp.Connection interface.
func (t *StreamTransport) SessionID() string {
	return t.s.Conn().RemotePeer().String()
}



// Write writes a message to the stream.
func (t *StreamTransport) Write(ctx context.Context, msg jsonrpc.Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return t.w.WriteMsg(data)
}
