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
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"

	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/google/sam/api"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p"
	gostream "github.com/libp2p/go-libp2p-gostream"
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

var ErrFatalAuth = errors.New("fatal authentication error")

type TrustedKey struct {
	Key        ed25519.PublicKey
	ReceivedAt time.Time
}

type nodeRelayACL struct {
	node *SamNode
}

func (a *nodeRelayACL) AllowReserve(p peer.ID, addr multiaddr.Multiaddr) bool {
	_, ok := a.node.authPeers.Load(p)
	return ok
}

func (a *nodeRelayACL) AllowConnect(src peer.ID, srcAddr multiaddr.Multiaddr, dest peer.ID) bool {
	_, ok := a.node.authPeers.Load(src)
	return ok
}

type SamNode struct {
	Host              host.Host
	DHT               *dht.IpfsDHT
	PubSub            *pubsub.PubSub
	Store             *Store
	HubPeerID         peer.ID
	peerLastEventTime map[string]int64
	receivedMsgs      map[string][]string
	topics            map[string]*pubsub.Topic
	mu                sync.Mutex
	LocalPolicy       *NodeConfigComplete
	revokedPeers      *lru.Cache[string, int64]
	verificationCache *lru.Cache[string, string]
	authPeers         sync.Map
	trustedKeys       []TrustedKey
	keysMu            sync.RWMutex
	rateLimiter       *PeerRateLimiter
	services          *ServiceRegistry
	BoundHTTPAddr     string
	AllowLoopback     bool
}

// NewSamNode creates a new Agent instance secured with the 4-layer pipeline.
func NewSamNode(ctx context.Context, privKey crypto.PrivKey, hubPubKey ed25519.PublicKey, hubAddrs []multiaddr.Multiaddr, store *Store, meshID string, discoveryInterval string, listenAddrs []string, enableRelay bool, nodeConfig *NodeConfigComplete, keyGracePeriod time.Duration, allowLoopback bool) (*SamNode, error) {
	var trustedKeys []TrustedKey
	if len(hubPubKey) > 0 {
		trustedKeys = []TrustedKey{{Key: hubPubKey, ReceivedAt: time.Now()}}
	}

	node := &SamNode{
		Store:        store,
		trustedKeys:  trustedKeys,
		peerLastEventTime: make(map[string]int64),
		receivedMsgs:      make(map[string][]string),
		topics:       make(map[string]*pubsub.Topic),
		LocalPolicy:   nodeConfig,
		AllowLoopback: allowLoopback,
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
		} else {
			logger.Warnf("Failed to parse static relay addr %s: %v", addr, err)
		}
	}
	logger.Infof("Configured %d static relays: %v", len(staticRelays), staticRelays)

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
		libp2p.AddrsFactory(func(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			if allowLoopback {
				return addrs
			}
			var filtered []multiaddr.Multiaddr
			for _, addr := range addrs {
				if !isLoopbackOrLinkLocal(addr) {
					filtered = append(filtered, addr)
				}
			}
			return filtered
		}),
	}

	// If we have a Hub, configure it as our static fallback relay for NAT hole-punching
	if len(staticRelays) > 0 {
		opts = append(opts, libp2p.EnableAutoRelayWithStaticRelays(staticRelays))
	}

	// If the user explicitly opts in, allow this node to serve as a relay for others
	if enableRelay {
		logger.Infof("[Relay] Enabling Relay Service")
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}
	node.Host = h

	if enableRelay {
		logger.Infof("[Relay] Enabling Relay Service with ACL")
		_, err = relay.New(h, relay.WithACL(&nodeRelayACL{node: node}))
		if err != nil {
			return nil, err
		}
	}

	// Initialize Rendezvous (DHT Client)
	kdht, err := dht.New(ctx, h, dht.Mode(dht.ModeAuto), dht.ProtocolPrefix("/sam"))
	if err != nil {
		return nil, err
	}
	node.DHT = kdht

	if err := kdht.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	node.services = NewServiceRegistry(node.DHT)

	// Bootstrap: Connect and Auth to the Hub
	var authenticated bool
	var fatalAuthErr error

	for _, addr := range hubAddrs {
		if err := node.ConnectAndAuthWithHub(ctx, addr); err != nil {
			logger.Warnf("[AuthN] Failed to bootstrap and auth with hub %s: %v", addr, err)
			if errors.Is(err, ErrFatalAuth) {
				fatalAuthErr = err
			}
		} else {
			authenticated = true
			break
		}
	}

	if len(hubAddrs) > 0 && !authenticated {
		if fatalAuthErr != nil {
			return nil, fmt.Errorf("fatal auth failure: %w", fatalAuthErr)
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

	// Start Ingress HTTP Server
	if err := node.StartIngressServer(ctx); err != nil {
		return nil, fmt.Errorf("failed to start ingress server: %w", err)
	}

	return node, nil
}

func (n *SamNode) RegisterStaticServices(ctx context.Context, services []api.ServiceConfig) error {
	// Wait for DHT to be ready (size > 0)
	// This avoids failure if we try to register immediately after enrollment
	// before the DHT has discovered peers.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	timeout := time.After(10 * time.Second) // 10 seconds timeout for DHT readiness

dhtLoop:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for DHT to be ready before registering static services")
		case <-ticker.C:
			if n.DHT.RoutingTable().Size() > 0 {
				break dhtLoop
			}
		}
	}

	var errs []error
	for _, sCfg := range services {
		req, err := buildRegisterRequest(sCfg)
		if err != nil {
			logger.Errorf("[ServiceRegistry] %v", err)
			errs = append(errs, err)
			continue
		}
		if err := n.RegisterService(ctx, req); err != nil {
			logger.Errorf("[ServiceRegistry] Failed to register static service %s: %v", sCfg.Name, err)
			errs = append(errs, fmt.Errorf("failed to register static service %s: %w", sCfg.Name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to register static services: %w", errors.Join(errs...))
	}
	return nil
}

func (n *SamNode) ConnectAndAuthWithHub(ctx context.Context, addr multiaddr.Multiaddr) error {
	addrInfo, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		return fmt.Errorf("failed to get AddrInfo from multiaddr: %w", err)
	}

	if err := n.Host.Connect(ctx, *addrInfo); err != nil {
		if strings.Contains(err.Error(), "peer id mismatch") {
			return fmt.Errorf("%w: %w", ErrFatalAuth, err)
		}
		return fmt.Errorf("failed to connect to hub %s: %w", addr, err)
	}

	n.HubPeerID = addrInfo.ID
	logger.Infof("[AuthN] Connected to hub: %s", addrInfo.ID)

	// Load biscuit from store
	biscuitBytes, err := n.Store.LoadIdentity()
	if err != nil {
		return fmt.Errorf("%w: failed to load identity from store: %w", ErrFatalAuth, err)
	}
	if len(biscuitBytes) == 0 {
		return fmt.Errorf("%w: no identity biscuit found in store", ErrFatalAuth)
	}

	// Open auth stream
	s, err := n.Host.NewStream(ctx, addrInfo.ID, api.AuthProtocolID)
	if err != nil {
		return fmt.Errorf("failed to open auth stream to hub: %w", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			logger.Debugf("failed to close stream: %v", err)
		}
	}()

	writer := msgio.NewVarintWriter(s)
	authFrame := &api.AuthFrame{Biscuit: biscuitBytes}
	data, err := proto.Marshal(authFrame)
	if err != nil {
		return fmt.Errorf("failed to marshal auth frame: %w", err)
	}
	if err := writer.WriteMsg(data); err != nil {
		return fmt.Errorf("failed to write auth frame: %w", err)
	}

	reader := msgio.NewVarintReaderSize(s, 1024*64)
	respMsg, err := reader.ReadMsg()
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}
	defer reader.ReleaseMsg(respMsg)

	var resp api.AuthResponse
	if err := proto.Unmarshal(respMsg, &resp); err != nil {
		return fmt.Errorf("failed to unmarshal auth response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("%w: auth failed: %s", ErrFatalAuth, resp.Error)
	}

	logger.Infof("[AuthN] Successfully authenticated with hub via libp2p")
	return nil
}

func (n *SamNode) StartRenewalLoop(ctx context.Context, issuerURL, clientID, clientSecret, jwtPath string) {
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
				if issuerURL != "" {
					tokenURL, err := n.DiscoverTokenURL(ctx, issuerURL)
					if err != nil {
						fmt.Printf("Failed to discover OIDC endpoints for renewal: %v\n", err)
						continue
					}
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

		// Since the signature is verified against our list of trusted hub public keys
		// in verifyEvent below, any message with a valid signature is cryptographically
		// proven to have been authored by one of the hubs. We do not restrict msg.GetFrom()
		// to a single HubPeerID because there can be multiple hub replicas in a cluster,
		// each with its own PeerID.

		if !n.verifyEvent(&event) {
			logger.Warnf("[Mesh Event] Potential spoofing attempt: invalid signature on event from %s", msg.ReceivedFrom)
			continue
		}

		// Freshness check: reject events older than the threshold to prevent replay attacks
        eventTime := time.UnixMilli(event.Timestamp)
        if time.Since(eventTime) > FreshnessThreshold || time.Until(eventTime) > FreshnessThreshold {
            logger.Warnf("[Mesh Event] Dropping stale or future event from %s (timestamp: %d)", msg.ReceivedFrom, event.Timestamp)
            continue
        }

		switch event.Type {
		case api.MeshEvent_BANNED:
			n.handleBannedEvent(&event)
		case api.MeshEvent_KEY_ROTATION:
			n.handleKeyRotationEvent(&event)
		}
	}
}



func (n *SamNode) handleBannedEvent(event *api.MeshEvent) {
	n.mu.Lock()
	if n.peerLastEventTime == nil {
		n.peerLastEventTime = make(map[string]int64)
	}
	if event.Timestamp < n.peerLastEventTime[event.PeerId] {
		logger.Warnf("[Mesh Event] Dropping out-of-order BANNED event for peer %s (event timestamp: %d, last processed: %d)", event.PeerId, event.Timestamp, n.peerLastEventTime[event.PeerId])
		n.mu.Unlock()
		return
	}
	n.peerLastEventTime[event.PeerId] = event.Timestamp

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
	if len(event.NewPublicKey) != ed25519.PublicKeySize {
		logger.Errorf("[Mesh Event] Key rotation failed: invalid public key size %d, expected %d", len(event.NewPublicKey), ed25519.PublicKeySize)
		return
	}
	logger.Infof("[Mesh Event] Key rotation received")
	n.keysMu.Lock()
	defer n.keysMu.Unlock()
	for _, tk := range n.trustedKeys {
		if bytes.Equal(tk.Key, event.NewPublicKey) {
			return // Ignore duplicate
		}
	}
	n.trustedKeys = append(n.trustedKeys, TrustedKey{Key: ed25519.PublicKey(event.NewPublicKey), ReceivedAt: time.Now()})
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

	n.authPeers.Store(remotePeer, true)
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

func (n *SamNode) RegisterService(ctx context.Context, req *api.RegisterServiceRequest) error {
	svc, err := NewServiceFromRequest(req)
	if err != nil {
		return err
	}
	return n.services.Register(ctx, svc)
}

func (n *SamNode) UnregisterService(ctx context.Context, serviceName string) error {
	return n.services.Unregister(ctx, serviceName)
}

// Teardown detaches all registered services and closes the libp2p host.
// Store is owned by the caller and is not closed here.
func (n *SamNode) Teardown() error {
	if n.services != nil {
		n.services.TeardownAll()
	}
	if n.Host != nil {
		return n.Host.Close()
	}
	return nil
}

func (n *SamNode) IsServiceRegistered(serviceName string) bool {
	_, ok := n.services.Get(serviceName)
	return ok
}

// Bound DHT lookups and per-peer catalog fan-out so a partially
// reachable mesh can't wedge a discovery call indefinitely.
const (
	dhtLookupTimeout       = 5 * time.Second
	discoveryFanoutTimeout = 5 * time.Second
)

// findProvidersByCID is the shared DHT-lookup primitive; bounds the
// lookup so FindProvidersAsync's channel is guaranteed to close.
func (n *SamNode) findProvidersByCID(ctx context.Context, c cid.Cid) ([]peer.AddrInfo, error) {
	if n.DHT == nil {
		return nil, fmt.Errorf("DHT not initialized")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
	defer cancel()
	// FindProvidersAsync can emit the same peer multiple times when the
	// DHT walk converges from different paths; dedupe so downstream
	// fan-out (e.g. discoverServicesByType) doesn't double-fetch.
	providersMap := make(map[peer.ID]peer.AddrInfo)
	for p := range n.DHT.FindProvidersAsync(lookupCtx, c, 20) {
		providersMap[p.ID] = p
	}
	providers := make([]peer.AddrInfo, 0, len(providersMap))
	for _, p := range providersMap {
		providers = append(providers, p)
	}
	return providers, nil
}

// FindProvidersByName returns peers hosting a specific {type, name} service.
func (n *SamNode) FindProvidersByName(ctx context.Context, serviceType api.ServiceType, serviceName string) ([]peer.AddrInfo, error) {
	c, err := serviceNameToCID(serviceType, serviceName)
	if err != nil {
		return nil, err
	}
	return n.findProvidersByCID(ctx, c)
}

// FindProvidersByType returns peers hosting at least one service of the given type.
func (n *SamNode) FindProvidersByType(ctx context.Context, serviceType api.ServiceType) ([]peer.AddrInfo, error) {
	c, err := serviceTypeToCID(serviceType)
	if err != nil {
		return nil, err
	}
	return n.findProvidersByCID(ctx, c)
}

// localProxyURL builds the loopback URL clients use to reach a remote service.
func (n *SamNode) localProxyURL(peerID peer.ID, typeStr, serviceName string) string {
	return fmt.Sprintf("http://%s/sam/%s/%s/%s",
		n.BoundHTTPAddr, peerID.String(), typeStr, serviceName)
}

// DiscoverRemoteServices dispatches to the named or type-only path
// based on whether serviceName is provided.
func (n *SamNode) DiscoverRemoteServices(ctx context.Context, serviceType api.ServiceType, serviceName string) ([]*api.DiscoveredProvider, error) {
	typeStr, err := serviceTypeToString(serviceType)
	if err != nil {
		return nil, err
	}
	if serviceName == "" {
		return n.discoverServicesByType(ctx, serviceType, typeStr)
	}
	return n.discoverServicesByName(ctx, serviceType, typeStr, serviceName)
}

// DiscoverRemoteServicesStream performs service discovery and streams results down the returned channel.
// The channel is closed automatically when discovery completes or the context is cancelled.
func (n *SamNode) DiscoverRemoteServicesStream(ctx context.Context, serviceType api.ServiceType, serviceName string) (<-chan *api.DiscoveredProvider, error) {
	typeStr, err := serviceTypeToString(serviceType)
	if err != nil {
		return nil, err
	}

	out := make(chan *api.DiscoveredProvider, 16)

	go func() {
		defer close(out)

		if serviceName != "" {
			peers, err := n.FindProvidersByName(ctx, serviceType, serviceName)
			if err != nil {
				logger.Errorf("[Discovery] FindProvidersByName failed: %v", err)
				return
			}
			for _, p := range peers {
				if p.ID == n.Host.ID() {
					continue
				}
				select {
				case <-ctx.Done():
					return
				case out <- &api.DiscoveredProvider{
					PeerId:        p.ID.String(),
					LocalProxyUrl: n.localProxyURL(p.ID, typeStr, serviceName),
					SrvName:       serviceName,
				}:
				}
			}
			return
		}

		peers, err := n.FindProvidersByType(ctx, serviceType)
		if err != nil {
			logger.Errorf("[Discovery] FindProvidersByType failed: %v", err)
			return
		}

		fanoutCtx, cancel := context.WithTimeout(ctx, discoveryFanoutTimeout)
		defer cancel()

		var wg sync.WaitGroup
		for _, p := range peers {
			if p.ID == n.Host.ID() {
				continue
			}
			wg.Add(1)
			go func(peerID peer.ID) {
				defer wg.Done()
				services, err := n.fetchRemoteServiceCatalog(fanoutCtx, peerID, typeStr)
				if err != nil {
					logger.Warnf("[Discovery] catalog fetch from %s failed: %v", peerID, err)
					return
				}
				for _, info := range services {
					dp := &api.DiscoveredProvider{
						PeerId:         peerID.String(),
						LocalProxyUrl:  n.localProxyURL(peerID, typeStr, info.Name),
						SrvName:        info.Name,
						SrvDescription: info.Description,
					}
					select {
					case <-fanoutCtx.Done():
						return
					case out <- dp:
					}
				}
			}(p.ID)
		}
		wg.Wait()
	}()

	return out, nil
}


// discoverServicesByName: targeted DHT lookup, no fan-out.
func (n *SamNode) discoverServicesByName(ctx context.Context, serviceType api.ServiceType, typeStr, serviceName string) ([]*api.DiscoveredProvider, error) {
	peers, err := n.FindProvidersByName(ctx, serviceType, serviceName)
	if err != nil {
		return nil, err
	}
	discovered := []*api.DiscoveredProvider{}
	for _, p := range peers {
		if p.ID == n.Host.ID() {
			continue
		}
		discovered = append(discovered, &api.DiscoveredProvider{
			PeerId:        p.ID.String(),
			LocalProxyUrl: n.localProxyURL(p.ID, typeStr, serviceName),
			SrvName:       serviceName,
		})
	}
	return discovered, nil
}

// discoverServicesByType: rendezvous lookup → parallel list_local_services
// fan-out → flat catalog. Failed peers are dropped with a log line.
func (n *SamNode) discoverServicesByType(ctx context.Context, serviceType api.ServiceType, typeStr string) ([]*api.DiscoveredProvider, error) {
	peers, err := n.FindProvidersByType(ctx, serviceType)
	if err != nil {
		return nil, err
	}

	fanoutCtx, cancel := context.WithTimeout(ctx, discoveryFanoutTimeout)
	defer cancel()

	type peerCatalog struct {
		peerID   peer.ID
		services []*api.ServiceInfo
	}
	results := make(chan peerCatalog, len(peers))
	var wg sync.WaitGroup
	for _, p := range peers {
		if p.ID == n.Host.ID() {
			continue
		}
		wg.Add(1)
		go func(peerID peer.ID) {
			defer wg.Done()
			services, err := n.fetchRemoteServiceCatalog(fanoutCtx, peerID, typeStr)
			if err != nil {
				logger.Warnf("[Discovery] catalog fetch from %s failed: %v", peerID, err)
				return
			}
			results <- peerCatalog{peerID: peerID, services: services}
		}(p.ID)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	discovered := []*api.DiscoveredProvider{}
	for r := range results {
		for _, info := range r.services {
			discovered = append(discovered, &api.DiscoveredProvider{
				PeerId:         r.peerID.String(),
				LocalProxyUrl:  n.localProxyURL(r.peerID, typeStr, info.Name),
				SrvName:        info.Name,
				SrvDescription: info.Description,
			})
		}
	}
	return discovered, nil
}

// ListLocalServices returns services registered on this node. If
// typeFilter is SERVICE_TYPE_UNSPECIFIED, all services are returned.
func (n *SamNode) ListLocalServices(typeFilter api.ServiceType) []*api.ServiceInfo {
	return n.services.List(typeFilter)
}

func (n *SamNode) StartIngressServer(ctx context.Context) error {
	listener, err := gostream.Listen(n.Host, "/libp2p-http")
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
			if len(parts) < 2 {
				http.Error(w, "Invalid path", http.StatusBadRequest)
				return
			}
			serviceTypeStr := parts[0]
			serviceName := parts[1]
			upstreamPath := ""
			if len(parts) > 2 {
				upstreamPath = parts[2]
			}

			serviceType, err := parseServiceType(serviceTypeStr)
			if err != nil || serviceType == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
				http.Error(w, "Invalid service type", http.StatusBadRequest)
				return
			}

			svc, ok := n.services.Get(serviceName)
			if !ok || svc.Handler() == nil {
				http.Error(w, "Service not found", http.StatusNotFound)
				return
			}

			r.URL.Path = "/" + upstreamPath
			svc.Handler().ServeHTTP(w, r)
		}),
	}

	go func() {
		logger.Infof("[Ingress] Starting P2P HTTP server on protocol /libp2p-http")
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logger.Errorf("[Ingress] Server error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		if err := server.Close(); err != nil {
			logger.Errorf("[Ingress] Failed to close server: %v", err)
		}
		if err := listener.Close(); err != nil {
			logger.Errorf("[Ingress] Failed to close listener: %v", err)
		}
	}()

	return nil
}

func isLoopbackOrLinkLocal(addr multiaddr.Multiaddr) bool {
	for _, proto := range addr.Protocols() {
		if proto.Code == multiaddr.P_IP4 || proto.Code == multiaddr.P_IP6 {
			value, err := addr.ValueForProtocol(proto.Code)
			if err == nil {
				ip := net.ParseIP(value)
				if ip != nil {
					if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
						return true
					}
				}
			}
		}
	}
	return false
}

