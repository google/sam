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
	"crypto/ed25519"
	"sync"

	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

const AuthProtocolID = protocol.ID("/sam/auth/1.0.0")

type SamNode struct {
	Host         host.Host
	DHT          *dht.IpfsDHT
	PubSub       *pubsub.PubSub
	Store        *Store
	HubPublicKey ed25519.PublicKey
	HubPeerID    peer.ID
	knownPeers   map[string]bool
	receivedMsgs map[string][]string
	topics       map[string]*pubsub.Topic
	mu           sync.Mutex
}

// NewSamNode creates a new Agent instance secured with the 4-layer pipeline.
func NewSamNode(ctx context.Context, privKey crypto.PrivKey, hubPubKey ed25519.PublicKey, hubAddrs []multiaddr.Multiaddr, store *Store, meshID string, discoveryInterval string, listenAddrs []string, enableRelay bool) (*SamNode, error) {
	node := &SamNode{
		Store:        store,
		HubPublicKey: hubPubKey,
		knownPeers:   make(map[string]bool),
		receivedMsgs: make(map[string][]string),
		topics:       make(map[string]*pubsub.Topic),
	}

	// Layer 2: Attach the Bouncer (Gater)
	gater := &nodeConnGate{node: node}

	// Convert Hub multiaddrs to peer.AddrInfo to use as static relays
	var staticRelays []peer.AddrInfo
	for _, addr := range hubAddrs {
		if addrInfo, err := peer.AddrInfoFromP2pAddr(addr); err == nil && addrInfo.ID != "" {
			staticRelays = append(staticRelays, *addrInfo)
		}
	}

	// Layer 1: Establish FIPS-compliant Transports & NAT Services
	opts := []libp2p.Option{
		libp2p.Identity(privKey),
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.ConnectionGater(gater),
		libp2p.ListenAddrStrings(listenAddrs...),
		libp2p.EnableNATService(),
	}

	// If we have a Hub, configure it as our static fallback relay for NAT hole-punching
	if len(staticRelays) > 0 {
		opts = append(opts, libp2p.EnableAutoRelayWithStaticRelays(staticRelays))
	}

	// If the user explicitly opts in, allow this node to serve as a relay for others
	if enableRelay {
		logger.Infof("[Relay] Enabling Relay Service")
		opts = append(opts, libp2p.EnableRelayService())
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}
	node.Host = h

	// Initialize Rendezvous (DHT Client)
	kdht, err := dht.New(ctx, h, dht.Mode(dht.ModeAuto))
	if err != nil {
		return nil, err
	}
	node.DHT = kdht

	if err := kdht.Bootstrap(ctx); err != nil {
		logger.Warnf("[DHT] Failed to bootstrap DHT: %v", err)
	}

	// Bootstrap: Connect to the Hub
	for _, addr := range hubAddrs {
		addrInfo, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil || addrInfo == nil {
			// Try to connect without Peer ID in address
			addrInfo = &peer.AddrInfo{
				Addrs: []multiaddr.Multiaddr{addr},
			}
			logger.Warn("[AuthN] Connecting to hub without Peer ID verification in address.")
		}
		if err := h.Connect(ctx, *addrInfo); err != nil {
			logger.Warnf("[AuthN] Failed to bootstrap to hub %s: %v", addr, err)
		} else {
			if addrInfo.ID == "" {
				// Discover Peer ID from connection
				for _, c := range h.Network().Conns() {
					if c.RemoteMultiaddr().Equal(addr) {
						node.HubPeerID = c.RemotePeer()
						logger.Infof("[AuthN] Connected to hub (discovered PeerID): %s", node.HubPeerID)
						break
					}
				}
			} else {
				node.HubPeerID = addrInfo.ID
				logger.Infof("[AuthN] Connected to hub: %s", addrInfo.ID)
			}
			break
		}
	}

	// Initialize Gossipsub for Hub Events
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, err
	}
	node.PubSub = ps

	// Listen for Network Evictions/Revocations from the Hub
	go node.listenForHubEvents(ctx)

	interval, err := time.ParseDuration(discoveryInterval)
	if err != nil {
		logger.Warnf("[Discovery] Invalid discovery interval '%s', using default 2s: %v", discoveryInterval, err)
		interval = 2 * time.Second
	}

	// Start DHT Discovery
	go node.startDiscovery(ctx, meshID, interval)

	// Layer 3: Open the Lobby Door (Auth Protocol is bypassed by Layer 4)
	node.Host.SetStreamHandler(AuthProtocolID, node.HandleAuthHandshake)

	// Layer 3: Wire up MCP handler wrapped in middleware
	node.Host.SetStreamHandler(api.MCPProtocolID, node.WithBiscuitAuth(node.HandleMCPStream))
	return node, nil
}

// listenForHubEvents listens to the topic established by the Hub
func (n *SamNode) listenForHubEvents(ctx context.Context) {
	topic, err := n.PubSub.Join(api.GossipEvents)
	if err != nil {
		return
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return
	}

	for {
		msg, err := sub.Next(ctx)
		if err != nil {
			return
		}
		var event api.MeshEvent
		if err := proto.Unmarshal(msg.Data, &event); err != nil {
			logger.Errorf("[Mesh Event] Failed to unmarshal event from %s: %v", msg.ReceivedFrom, err)
			continue
		}

		n.mu.Lock()
		switch event.Type {
		case api.MeshEvent_JOIN:
			n.knownPeers[event.PeerId] = true
			logger.Infof("[Mesh Event] Peer joined: %s", event.PeerId)
		case api.MeshEvent_EXIT, api.MeshEvent_BANNED:
			delete(n.knownPeers, event.PeerId)
			logger.Infof("[Mesh Event] Peer left/banned: %s", event.PeerId)
		}
		n.mu.Unlock()
	}
}

func (n *SamNode) subscribeToTopic(ctx context.Context, topicName string) error {
	n.mu.Lock()
	topic, ok := n.topics[topicName]
	var err error
	if !ok {
		topic, err = n.PubSub.Join(topicName)
		if err == nil {
			n.topics[topicName] = topic
		}
	}
	n.mu.Unlock()
	if err != nil {
		return err
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return err
	}

	bgCtx := context.Background()
	go func() {
		defer sub.Cancel()
		for {
			msg, err := sub.Next(bgCtx)
			if err != nil {
				return
			}
			n.mu.Lock()
			n.receivedMsgs[topicName] = append(n.receivedMsgs[topicName], string(msg.Data))
			n.mu.Unlock()
		}
	}()
	return nil
}

func (n *SamNode) startDiscovery(ctx context.Context, meshID string, interval time.Duration) {
	routingDiscovery := routing.NewRoutingDiscovery(n.DHT)
	util.Advertise(ctx, routingDiscovery, meshID)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			peers, err := routingDiscovery.FindPeers(ctx, meshID)
			if err != nil {
				logger.Errorf("[Discovery] Failed to find peers: %v", err)
				continue
			}
			for p := range peers {
				if p.ID == n.Host.ID() {
					continue
				}
				n.mu.Lock()
				if !n.knownPeers[p.ID.String()] {
					n.knownPeers[p.ID.String()] = true
					logger.Infof("[Discovery] Found new peer via DHT: %s", p.ID)
					go func(pi peer.AddrInfo) {
						if err := n.Host.Connect(ctx, pi); err != nil {
							logger.Errorf("[Discovery] Failed to connect to %s: %v", pi.ID, err)
						}
					}(p)
				}
				n.mu.Unlock()
			}
		}
	}
}

// HandleAuthHandshake is the core libp2p stream handler for /sam/auth/1.0.0.
// This is the "Admission Office" of the mesh node.
func (n *SamNode) HandleAuthHandshake(s network.Stream) {
	defer func() {
		if err := s.Close(); err != nil {
			logger.Errorf("[AuthN] Failed to close auth stream: %v", err)
		}
	}()
	remotePeer := s.Conn().RemotePeer()

	reader := msgio.NewVarintReaderSize(s, 1024*64)
	msg, err := reader.ReadMsg()
	if err != nil {
		logger.Errorf("[AuthN] Failed to read handshake from %s: %v", remotePeer, err)
		return
	}
	defer reader.ReleaseMsg(msg)

	var exchange api.AuthEnvelope
	if err := proto.Unmarshal(msg, &exchange); err != nil {
		logger.Warnf("[AuthN] Invalid protobuf from %s", remotePeer)
		return
	}

	// 2. Unmarshal and verify token format
	b, err := biscuit.Unmarshal(exchange.Biscuit)
	if err != nil {
		logger.Warnf("[AuthN] Malformed biscuit from %s", remotePeer)
		return
	}

	// 3. Verify signature chain against the trusted Hub key.
	authorizer, err := b.Authorizer(n.HubPublicKey)
	if err != nil {
		logger.Errorf("[AuthN] Signature verification setup failed for %s: %v", remotePeer, err)
		return
	}
	if err := authorizer.Authorize(); err != nil {
		logger.Warnf("[AuthN] Authorization failed for %s: %v", remotePeer, err)
		return
	}

	// 4. Enforce hardware binding: token must include node(<remotePeerID>)
	boundFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}
	if _, err := b.GetBlockID(boundFact); err != nil {
		logger.Warnf("[AuthN] Token is not bound to peer %s", remotePeer)
		return
	}

	// Query for the standard facts we mapped in the Hub
	// user_id, user_email, group, mesh_id
	// Note: We use the authorizer to extract these values from the Datalog state
	identity := VerifiedIdentity{
		RawBiscuit: exchange.Biscuit,
		// In a full implementation, you would use authorizer.Query()
		// to extract specific strings like user_id and group.
		NodeID:    remotePeer.String(), // Placeholder for Datalog query result
		UserID:    "extracted_id",      // Placeholder for Datalog query result
		UserEmail: "extracted_email",   // Placeholder for Datalog query result
		MeshID:    "extracted_mesh",    // Placeholder for Datalog query result
	}

	// 5. Save to the persistent session cache (BoltDB)
	// Once saved here, the ConnectionGater and Middleware will "recognize" this peer.
	if err := n.Store.SaveVerifiedIdentity(remotePeer, identity); err != nil {
		logger.Errorf("[AuthN] Store error for %s: %v", remotePeer, err)
		return
	}

	logger.Infof("[AuthN] Successfully authenticated peer %s (%s)", remotePeer, identity.UserEmail)
}
