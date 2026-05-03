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
	"os"
	"strings"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/google/sam/api"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

const (
	// Cache sizes
	RateLimiterSize       = 1000
	RevocationCacheSize   = 10000
	VerificationCacheSize = 1000

	// Freshness checks
	FreshnessThreshold = 5 * time.Minute

	// Key pruning
	KeyPruningInterval = 1 * time.Hour
)

type TrustedKey struct {
	Key        ed25519.PublicKey
	ReceivedAt time.Time
}

type SamNode struct {
	Host              host.Host
	DHT               *dht.IpfsDHT
	PubSub            *pubsub.PubSub
	Store             *Store
	HubPeerID         peer.ID
	knownPeers        map[string]bool
	receivedMsgs      map[string][]string
	topics            map[string]*pubsub.Topic
	mu                sync.Mutex
	LocalPolicy       *CompiledLocalPolicy
	revokedPeers      *lru.Cache[string, int64]
	verificationCache *lru.Cache[string, string]
	trustedKeys       []TrustedKey
	keysMu            sync.RWMutex
	rateLimiter       *PeerRateLimiter
}

// NewSamNode creates a new Agent instance secured with the 4-layer pipeline.
func NewSamNode(ctx context.Context, privKey crypto.PrivKey, hubPubKey ed25519.PublicKey, hubAddrs []multiaddr.Multiaddr, store *Store, meshID string, discoveryInterval string, listenAddrs []string, enableRelay bool, localPolicy *CompiledLocalPolicy, keyGracePeriod time.Duration) (*SamNode, error) {
	var trustedKeys []TrustedKey
	if len(hubPubKey) > 0 {
		trustedKeys = []TrustedKey{{Key: hubPubKey, ReceivedAt: time.Now()}}
	}

	node := &SamNode{
		Store:        store,
		trustedKeys:  trustedKeys,
		knownPeers:   make(map[string]bool),
		receivedMsgs: make(map[string][]string),
		topics:       make(map[string]*pubsub.Topic),
		LocalPolicy:  localPolicy,
	}

	var err error
	node.rateLimiter, err = NewPeerRateLimiter(RateLimiterSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create rate limiter: %w", err)
	}
	node.revokedPeers, err = lru.New[string, int64](RevocationCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create revocation cache: %w", err)
	}

	node.verificationCache, err = lru.New[string, string](VerificationCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create verification cache: %w", err)
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

	cm, err := connmgr.NewConnManager(100, 400, connmgr.WithGracePeriod(time.Minute))
	if err != nil {
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
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
		libp2p.ConnectionManager(cm),
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
		logger.Warnf("[Discovery] Invalid discovery interval '%s', using default %s: %v", discoveryInterval, DefaultDiscoveryInterval, err)
		interval, _ = time.ParseDuration(DefaultDiscoveryInterval)
	}

	// Start DHT Discovery
	go node.startDiscovery(ctx, meshID, interval)

	// Layer 3: Open the Lobby Door (Auth Protocol is bypassed by Layer 4)
	node.Host.SetStreamHandler(api.AuthProtocolID, node.HandleAuthHandshake)

	// Layer 3: Wire up MCP handler wrapped in middleware
	node.Host.SetStreamHandler(api.MCPProtocolID, node.WithBiscuitAuth(node.HandleMCPStream))

	// Start key pruning
	node.startKeyPruning(ctx, keyGracePeriod)

	return node, nil
}

func (n *SamNode) StartRenewalLoop(ctx context.Context, tokenURL, clientID, clientSecret, jwtPath string) {
	go func() {
		for {
			var renewAfter = DefaultRenewalFallback // Default fallback

			exp, err := n.Store.LoadIdentityExpiration()
			if err == nil && exp > 0 {
				expTime := time.Unix(exp, 0)
				duration := time.Until(expTime)
				if duration > RenewalThreshold {
					renewAfter = duration - RenewalBuffer
				} else if duration > 0 {
					renewAfter = duration / 2
				} else {
					renewAfter = 1 * time.Minute
				}
			}

			fmt.Printf("[Auth] Next renewal in %v\n", renewAfter)
			timer := time.NewTimer(renewAfter)

			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				fmt.Println("Renewing enrollment...")
				var newJWT string
				if tokenURL != "" {
					var err error
					newJWT, err = n.FetchJWT(ctx, tokenURL, clientID, clientSecret)
					if err != nil {
						fmt.Printf("Failed to fetch JWT for renewal: %v\n", err)
						continue
					}
				} else if jwtPath != "" {
					data, err := os.ReadFile(jwtPath)
					if err != nil {
						fmt.Printf("Failed to read JWT file for renewal: %v\n", err)
						continue
					}
					newJWT = strings.TrimSpace(string(data))
				} else {
					fmt.Println("No credentials available for renewal.")
					continue
				}

				if err := n.Enroll(ctx, newJWT); err != nil {
					fmt.Printf("Renewal enrollment failed: %v\n", err)
				} else {
					fmt.Println("Enrollment renewed successfully.")
				}
			}
		}
	}()
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

		if !n.rateLimiter.Allow(msg.ReceivedFrom.String()) {
			logger.Warnf("[Mesh Event] Rate limit exceeded for %s, dropping message", msg.ReceivedFrom)
			continue
		}

		var event api.MeshEvent
		if err := proto.Unmarshal(msg.Data, &event); err != nil {
			logger.Errorf("[Mesh Event] Failed to unmarshal event from %s: %v", msg.ReceivedFrom, err)
			continue
		}

		// use the original author not the one that just relay the message
		if msg.GetFrom() != n.HubPeerID {
			logger.Warnf("[Mesh Event] Ignored event from non-hub peer: %s", msg.ReceivedFrom)
			continue
		}

		if !n.verifyEvent(&event) {
			logger.Warnf("[Mesh Event] Potential spoofing attempt: invalid signature on event from %s", msg.ReceivedFrom)
			continue
		}

		// Freshness check: reject events older than the threshold to prevent replay attacks
		if time.Since(time.Unix(event.Timestamp, 0)) > FreshnessThreshold {
			logger.Warnf("[Mesh Event] Dropping stale event from %s (timestamp: %d)", msg.ReceivedFrom, event.Timestamp)
			continue
		}

		switch event.Type {
		case api.MeshEvent_JOIN:
			n.handleJoinEvent(&event)
		case api.MeshEvent_EXIT:
			n.handleExitEvent(&event)
		case api.MeshEvent_BANNED:
			n.handleBannedEvent(&event)
		case api.MeshEvent_KEY_ROTATION:
			n.handleKeyRotationEvent(&event)
		}
	}
}

func (n *SamNode) handleJoinEvent(event *api.MeshEvent) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Host == nil || event.PeerId != n.Host.ID().String() {
		n.knownPeers[event.PeerId] = true
	}
	logger.Infof("[Mesh Event] Peer joined: %s", event.PeerId)
}

func (n *SamNode) handleExitEvent(event *api.MeshEvent) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.knownPeers, event.PeerId)
	logger.Infof("[Mesh Event] Peer left: %s", event.PeerId)
}

func (n *SamNode) handleBannedEvent(event *api.MeshEvent) {
	n.mu.Lock()
	delete(n.knownPeers, event.PeerId)
	n.mu.Unlock()

	logger.Infof("[Mesh Event] Peer banned: %s", event.PeerId)

	n.revokedPeers.Add(event.PeerId, event.Timestamp)
	if p, err := peer.Decode(event.PeerId); err == nil {
		if n.Host != nil {
			_ = n.Host.Network().ClosePeer(p)
		}
	}
}

func (n *SamNode) handleKeyRotationEvent(event *api.MeshEvent) {
	logger.Infof("[Mesh Event] Key rotation received")
	n.keysMu.Lock()
	n.trustedKeys = append(n.trustedKeys, TrustedKey{Key: ed25519.PublicKey(event.NewPublicKey), ReceivedAt: time.Now()})
	n.keysMu.Unlock()
}

func (n *SamNode) startKeyPruning(ctx context.Context, gracePeriod time.Duration) {
	if gracePeriod <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(KeyPruningInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				logger.Info("[KeyPruning] Pruning expired keys...")
				n.keysMu.Lock()
				now := time.Now()
				var activeKeys []TrustedKey
				for _, tk := range n.trustedKeys {
					if now.Sub(tk.ReceivedAt) <= gracePeriod {
						activeKeys = append(activeKeys, tk)
					}
				}
				n.trustedKeys = activeKeys
				n.keysMu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (n *SamNode) verifyEvent(event *api.MeshEvent) bool {
	sig := event.Signature
	event.Signature = nil
	data, err := proto.Marshal(event)
	event.Signature = sig // Restore
	if err != nil {
		logger.Errorf("[Mesh Event] Failed to marshal event for verification: %v", err)
		return false
	}

	n.keysMu.RLock()
	keys := n.trustedKeys
	n.keysMu.RUnlock()

	for _, tk := range keys {
		if len(tk.Key) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(tk.Key, data, sig) {
			return true
		}
	}
	return false
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
				n.knownPeers[p.ID.String()] = true
				n.mu.Unlock()

				if n.Host.Network().Connectedness(p.ID) != network.Connected {
					logger.Infof("[Discovery] Found peer not connected via DHT: %s", p.ID)
					go func(pi peer.AddrInfo) {
						if err := n.Host.Connect(ctx, pi); err != nil {
							logger.Errorf("[Discovery] Failed to connect to %s: %v", pi.ID, err)
						}
					}(p)
				}
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

	var exchange api.AuthFrame
	if err := proto.Unmarshal(msg, &exchange); err != nil {
		logger.Warnf("[AuthN] Invalid protobuf from %s", remotePeer)
		return
	}

	b, err := n.verifyBiscuit(exchange.Biscuit, remotePeer)
	if err != nil {
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

	logger.Infof("[AuthN] Successfully authenticated peer %s", remotePeer)
}

func (n *SamNode) verifyBiscuit(biscuitData []byte, remotePeer peer.ID) (*biscuit.Biscuit, error) {
	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		return nil, fmt.Errorf("malformed biscuit: %w", err)
	}

	tokenHash := sha256.Sum256(biscuitData)
	hashStr := hex.EncodeToString(tokenHash[:]) + ":" + remotePeer.String()

	if pubKeyStr, ok := n.verificationCache.Get(hashStr); ok {
		n.keysMu.RLock()
		keys := n.trustedKeys
		n.keysMu.RUnlock()

		for _, tk := range keys {
			if hex.EncodeToString(tk.Key) == pubKeyStr {
				return b, nil
			}
		}
	}

	n.keysMu.RLock()
	keys := n.trustedKeys
	n.keysMu.RUnlock()

	for _, tk := range keys {
		if len(tk.Key) != ed25519.PublicKeySize {
			continue
		}
		authorizer, err := b.Authorizer(tk.Key)
		if err != nil {
			continue
		}

		rule, err := parser.FromStringPolicy("allow if true")
		if err != nil {
			continue
		}
		authorizer.AddPolicy(rule)

		if err := authorizer.Authorize(); err == nil {
			n.verificationCache.Add(hashStr, hex.EncodeToString(tk.Key))
			return b, nil
		}
	}

	return nil, fmt.Errorf("no valid key found")
}
