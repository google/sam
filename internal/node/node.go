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

package node

import (
	"math/rand"

	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"

	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/ipfs/go-cid"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p"
	gostream "github.com/libp2p/go-libp2p-gostream"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	records "github.com/libp2p/go-libp2p-kad-dht/records"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	"google.golang.org/protobuf/proto"
)

// PeerstoreKeyPrivateIPFailed is the key used in the libp2p Peerstore to track
// if a peer's private IP was previously found to be unreachable or slower than a relay.
// This allows the node to "try once and remember", avoiding a 15-second timeout on
// subsequent discovery or tool calls when dialing unroutable private networks.
const PeerstoreKeyPrivateIPFailed = "private_ip_failed"

// maxMeshProactiveConnections is the target maximum number of active mesh connections.
// If active connections count reaches this threshold, the node skips periodic DHT peer discovery.
const maxMeshProactiveConnections = 30

const (
	// Cache sizes
	RateLimiterSize       = 1000
	RevocationCacheSize   = 10000
	VerificationCacheSize = 1000

	// Freshness checks
	FreshnessThreshold = 5 * time.Minute

	// Key pruning
	KeyPruningInterval = 1 * time.Hour

	// Reprovide interval
	ReprovideInterval = 5 * time.Minute
)

var (
	// Renewal timing defaults
	DefaultRenewalFallback = (api.BiscuitTokenTTL * 8) / 10 // 80% of TTL (19.2h)
	RenewalBuffer          = api.BiscuitTokenTTL / 5        // 20% of TTL (4.8h)
	RenewalThreshold       = api.BiscuitTokenTTL / 4        // 25% of TTL (6h)
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
	_, ok := a.node.authPeers.Load(dest)
	return ok
}

type SamNode struct {
	config            Options
	Host              host.Host
	DHT               *dht.IpfsDHT
	PubSub            *pubsub.PubSub
	Store             *Store
	HubPeerID         peer.ID
	authenticatedHubs map[peer.ID]bool
	peerLastEventTime map[string]int64
	receivedMsgs      map[string][]string
	topics            map[string]*pubsub.Topic
	mu                sync.Mutex
	LocalPolicy       *NodeConfigComplete
	revokedPeers      *lru.Cache[string, int64]
	authPeers         sync.Map
	trustedKeys       []TrustedKey
	keysMu            sync.RWMutex
	rateLimiter       *PeerRateLimiter
	services          *ServiceRegistry
	BoundHTTPAddr     string
	AllowLoopback     bool

	authSuccess      chan struct{}
	authOnce         sync.Once
	currentRelays    []peer.AddrInfo
	reprovideTrigger chan struct{}
	BiscuitTimeout   time.Duration
	cachedIdentity   atomic.Value
	logger           *golog.ZapEventLogger
}

// UpdateRelays updates the current relays used by AutoRelay.
func (n *SamNode) UpdateRelays(addrs []multiaddr.Multiaddr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var newRelays []peer.AddrInfo
	for _, addr := range addrs {
		resolvedAddrs, err := resolveAddrIfNeeded(context.Background(), addr)
		if err != nil {
			resolvedAddrs = []multiaddr.Multiaddr{addr}
		}
		for _, resolved := range resolvedAddrs {
			if addrInfo, err := peer.AddrInfoFromP2pAddr(resolved); err == nil && addrInfo.ID != "" {
				newRelays = append(newRelays, *addrInfo)
				n.Host.Peerstore().AddAddrs(addrInfo.ID, addrInfo.Addrs, peerstore.PermanentAddrTTL)
			}
		}
	}
	n.currentRelays = newRelays
	logger.Infof("[Relay] Updated current relays for AutoRelay: %v", newRelays)
}

// GetIdentity returns the node's biscuit identity, caching it in memory.
func (n *SamNode) GetIdentity() []byte {
	if val := n.cachedIdentity.Load(); val != nil {
		b := val.([]byte)
		if len(b) > 0 {
			return b
		}
	}
	if n.Store != nil {
		if biscuitBytes, err := n.Store.LoadIdentity(); err == nil && len(biscuitBytes) > 0 {
			n.cachedIdentity.Store(biscuitBytes)
			return biscuitBytes
		}
	}
	return nil
}

// SetIdentityCache explicitly updates the cached identity.
func (n *SamNode) SetIdentityCache(b []byte) {
	if len(b) > 0 {
		n.cachedIdentity.Store(b)
	}
}

func stripP2pFromDnsaddr(addr multiaddr.Multiaddr) multiaddr.Multiaddr {
	_, err := addr.ValueForProtocol(multiaddr.P_DNSADDR)
	if err != nil {
		return addr
	}
	parts := multiaddr.Split(addr)
	var components []multiaddr.Multiaddrer
	for _, p := range parts {
		if _, err := p.ValueForProtocol(multiaddr.P_P2P); err != nil {
			components = append(components, multiaddr.Multiaddr{p})
		}
	}
	if len(components) > 0 {
		return multiaddr.Join(components...)
	}
	return addr
}

func resolveAddrIfNeeded(ctx context.Context, addr multiaddr.Multiaddr) ([]multiaddr.Multiaddr, error) {
	_, err := addr.ValueForProtocol(multiaddr.P_DNSADDR)
	if err != nil {
		return []multiaddr.Multiaddr{addr}, nil
	}
	return madns.DefaultResolver.Resolve(ctx, stripP2pFromDnsaddr(addr))
}

// NewSamNode creates a new Agent instance secured with the 4-layer pipeline.
// NewSamNode initializes options and structures without starting background tasks or network interfaces.
func NewSamNode(cfg Options) (*SamNode, error) {
	cfg.Default()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var trustedKeys []TrustedKey
	if len(cfg.HubPubKey) > 0 {
		trustedKeys = []TrustedKey{{Key: cfg.HubPubKey, ReceivedAt: time.Now()}}
	}

	node := &SamNode{
		config:            cfg,
		Store:             cfg.Store,
		trustedKeys:       trustedKeys,
		peerLastEventTime: make(map[string]int64),
		receivedMsgs:      make(map[string][]string),
		topics:            make(map[string]*pubsub.Topic),
		authenticatedHubs: make(map[peer.ID]bool),
		LocalPolicy:       cfg.NodeConfig,
		AllowLoopback:     cfg.AllowLoopback,
		authSuccess:       make(chan struct{}),
		reprovideTrigger:  make(chan struct{}, 1),
		logger:            golog.Logger("sam-node"),
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

	return node, nil
}

// Start initializes the libp2p host, DHT, connects to the hub, and starts runtime components.
func (n *SamNode) Start(ctx context.Context) error {
	if biscuitBytes := n.GetIdentity(); len(biscuitBytes) > 0 {
		hubPubKeyBytes, _, err := n.Store.LoadHubConfig()
		if err == nil && len(hubPubKeyBytes) > 0 {
			if err := identity.VerifyBiscuitRole(biscuitBytes, ed25519.PublicKey(hubPubKeyBytes), n.config.RequiredRole); err != nil {
				return fmt.Errorf("loaded identity fails role requirement %q: %w", n.config.RequiredRole, err)
			}
		}
	}

	// Layer 2: Attach the Bouncer (Gater)
	gater := &nodeConnGate{node: n}

	// Convert Hub multiaddrs to peer.AddrInfo to use as static relays
	var staticRelays []peer.AddrInfo
	for _, addr := range n.config.HubAddrs {
		resolvedAddrs, err := resolveAddrIfNeeded(ctx, addr)
		if err != nil {
			resolvedAddrs = []multiaddr.Multiaddr{addr}
		}
		for _, resolved := range resolvedAddrs {
			if addrInfo, err := peer.AddrInfoFromP2pAddr(resolved); err == nil && addrInfo.ID != "" {
				staticRelays = append(staticRelays, *addrInfo)
				if n.HubPeerID == "" {
					n.HubPeerID = addrInfo.ID
				}
			} else {
				logger.Warnf("Failed to parse static relay addr %s: %v", resolved, err)
			}
		}
	}
	logger.Infof("Configured %d static relays: %v", len(staticRelays), staticRelays)

	cm, err := connmgr.NewConnManager(100, 400, connmgr.WithGracePeriod(time.Minute))
	if err != nil {
		return fmt.Errorf("failed to create connection manager: %w", err)
	}

	// Layer 1: Establish FIPS-compliant Transports & NAT Services
	opts := []libp2p.Option{
		libp2p.Identity(n.config.PrivKey),
		libp2p.DefaultTransports,
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.ConnectionGater(gater),
		libp2p.ListenAddrStrings(n.config.ListenAddrs...),
		libp2p.EnableNATService(),
		libp2p.EnableAutoNATv2(),
		libp2p.ForceReachabilityPrivate(),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
		libp2p.ConnectionManager(cm),
		libp2p.SwarmOpts(swarm.WithDialTimeout(15 * time.Second)),
		libp2p.AddrsFactory(func(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			if n.config.AllowLoopback {
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
		n.currentRelays = staticRelays
		opts = append(opts, libp2p.EnableAutoRelayWithPeerSource(
			func(ctx context.Context, numPeers int) <-chan peer.AddrInfo {
				logger.Infof("[Relay] AutoRelay called PeerSource for %d peers", numPeers)
				n.mu.Lock()
				currentRelays := n.currentRelays
				n.mu.Unlock()

				c := make(chan peer.AddrInfo, len(currentRelays))
				go func() {
					defer close(c)
					select {
					case <-ctx.Done():
						logger.Infof("[Relay] PeerSource context done")
					case <-n.authSuccess:
						logger.Infof("[Relay] Yielding static relays to AutoRelay")
						// Shuffle the relays to distribute load evenly across Hubs
						shuffled := make([]peer.AddrInfo, len(currentRelays))
						copy(shuffled, currentRelays)
						rand.Shuffle(len(shuffled), func(i, j int) {
							shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
						})
						for _, r := range shuffled {
							c <- r
						}
					}
				}()
				return c
			},
			autorelay.WithBootDelay(n.config.AutoRelayBootDelay),
			autorelay.WithBackoff(n.config.AutoRelayBackoff),
			autorelay.WithMinInterval(n.config.AutoRelayMinInterval),
		))
	}

	// If the user explicitly opts in, allow this node to serve as a relay for others
	if n.config.EnableRelay {
		logger.Infof("[Relay] Enabling Relay Service")
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return err
	}
	n.Host = h

	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, c network.Conn) {
			remotePeer := c.RemotePeer()
			remoteAddr := c.RemoteMultiaddr()
			if hasCircuit(remoteAddr) || !isPrivateIP(remoteAddr) {
				if err := h.Peerstore().Put(remotePeer, PeerstoreKeyPrivateIPFailed, true); err != nil {
					logger.Errorf("[Discovery] Failed to put peerstore private IP failed key: %v", err)
				}
				logger.Debugf("[Discovery] Peer %s connected via relay/public IP (%s), marking private IP as failed", remotePeer, remoteAddr)
			}
		},
	})

	// Permanently add the static relay address to the peerstore so we can build relay paths later
	for _, pi := range staticRelays {
		h.Peerstore().AddAddrs(pi.ID, pi.Addrs, peerstore.PermanentAddrTTL)
	}

	if n.config.EnableRelay {
		logger.Infof("[Relay] Enabling Relay Service with ACL")
		_, err = relay.New(h, relay.WithACL(&nodeRelayACL{node: n}))
		if err != nil {
			return err
		}
	}

	// Initialize Rendezvous (DHT Client)
	dhtOpts := []dht.Option{
		dht.Mode(dht.ModeAuto),
		dht.ProtocolPrefix("/sam"),
	}
	var pmOpts []records.Option
	if n.config.DHTProviderAddrTTL > 0 {
		pmOpts = append(pmOpts, records.ProviderAddrTTL(n.config.DHTProviderAddrTTL))
		pmOpts = append(pmOpts, records.ProvideValidity(n.config.DHTProviderAddrTTL))
	}
	if len(pmOpts) > 0 {
		dhtOpts = append(dhtOpts, dht.ProviderManagerOpts(pmOpts...))
	}
	if n.config.DHTMaxRecordAge > 0 {
		dhtOpts = append(dhtOpts, dht.MaxRecordAge(n.config.DHTMaxRecordAge))
	}
	kdht, err := dht.New(ctx, h, dhtOpts...)
	if err != nil {
		return err
	}
	n.DHT = kdht

	n.services = NewServiceRegistry(n.DHT)

	var authenticated bool
	var fatalAuthErr error

	for _, addr := range n.config.HubAddrs {
		if err := n.ConnectAndAuthWithHub(ctx, addr); err != nil {
			logger.Warnf("[AuthN] Failed to bootstrap and auth with hub %s: %v", addr, err)
			if errors.Is(err, ErrFatalAuth) {
				fatalAuthErr = err
			}
		} else {
			authenticated = true
		}
	}

	if len(n.config.HubAddrs) > 0 && !authenticated {
		if fatalAuthErr != nil {
			return fmt.Errorf("fatal auth failure: %w", fatalAuthErr)
		}
		return fmt.Errorf("failed to authenticate with any hub: all connection attempts failed")
	}

	if authenticated {
		logger.Infof("[DHT] Bootstrapping DHT with connected hub...")
		if err := n.DHT.Bootstrap(ctx); err != nil {
			logger.Warnf("[DHT] Failed to trigger DHT bootstrap: %v", err)
		}
	}

	// Initialize Gossipsub for Hub Events
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return err
	}
	n.PubSub = ps

	// Subscribe to local address updates to reprovide services and log
	sub, err := h.EventBus().Subscribe(new(event.EvtLocalAddressesUpdated))
	if err == nil {
		go func() {
			defer sub.Close() //nolint:errcheck
			for {
				select {
				case <-ctx.Done():
					return
				case e, ok := <-sub.Out():
					if !ok {
						return
					}
					evt, ok := e.(event.EvtLocalAddressesUpdated)
					if !ok {
						logger.Warnf("[Network] Unexpected event type received: %T", e)
						continue
					}

					var addrs []multiaddr.Multiaddr
					for _, a := range evt.Current {
						addrs = append(addrs, a.Address)
					}
					logger.Infof("[Network] Local addresses updated: %v", addrs)

					// Debounce and trigger unified reprovide loop
					go func() {
						time.Sleep(2 * time.Second) // Small debounce
						select {
						case n.reprovideTrigger <- struct{}{}:
						default:
						}
					}()
				}
			}
		}()
	}

	// Listen for Network Evictions/Revocations from the Hub
	go n.listenForHubEvents(ctx)

	interval, err := time.ParseDuration(n.config.DiscoveryInterval)
	if err != nil {
		logger.Warnf("[Discovery] Invalid discovery interval '%s', using default %s: %v", n.config.DiscoveryInterval, DefaultDiscoveryInterval, err)
		interval, _ = time.ParseDuration(DefaultDiscoveryInterval)
	}

	// Start DHT Discovery
	go n.startDiscovery(ctx, n.config.MeshID, interval)

	// Layer 3: Open the Lobby Door (Auth Protocol is bypassed by Layer 4)
	n.Host.SetStreamHandler(api.AuthProtocolID, n.HandleAuthHandshake)

	// Layer 3: Wire up MCP handler wrapped in middleware
	n.Host.SetStreamHandler(api.MCPProtocolID, n.WithBiscuitAuth(n.HandleMCPStream))

	// Start key pruning
	n.startKeyPruning(ctx, n.config.KeyGracePeriod)

	// Start Ingress HTTP Server
	if err := n.StartIngressServer(ctx); err != nil {
		return fmt.Errorf("failed to start ingress server: %w", err)
	}

	// Start connection monitor
	n.startConnectionMonitor(ctx, n.config.MonitorBootstrap, n.config.MonitorInterval, 3)

	// Periodically and on-demand reprovide registered services to the DHT
	n.startReprovideLoop(ctx, ReprovideInterval)

	return nil
}

func (n *SamNode) startReprovideLoop(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Run an initial reprovide after a short delay to let DHT bootstrap stabilize
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			n.services.ReprovideAll(ctx)
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n.services.ReprovideAll(ctx)
			case <-n.reprovideTrigger:
				n.services.ReprovideAll(ctx)
			}
		}
	}()
}

func (n *SamNode) IsConnected() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.authenticatedHubs) == 0 {
		return false
	}
	for pid := range n.authenticatedHubs {
		if n.Host.Network().Connectedness(pid) == network.Connected {
			return true
		}
	}
	return false
}

func (n *SamNode) LoadHubConfig() ([]byte, []string, error) {
	return n.Store.LoadHubConfig()
}

func (n *SamNode) LoadHubURL() (string, error) {
	return n.Store.LoadHubURL()
}

func (n *SamNode) SaveHubConfig(pubKey []byte, addrs []string) error {
	return n.Store.SaveHubConfig(pubKey, addrs)
}

func (n *SamNode) startConnectionMonitor(ctx context.Context, bootstrapDuration, checkInterval time.Duration, maxFailures int) {
	go func() {
		// Wait for initial bootstrap to complete
		select {
		case <-ctx.Done():
			return
		case <-time.After(bootstrapDuration):
		}

		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		consecutiveFailures := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stable, reconnected := checkHubConnection(ctx, n)

				if stable {
					if consecutiveFailures > 0 {
						logger.Infof("[Monitor] Connection to hub is stable. Resetting failure count.")
						consecutiveFailures = 0
					}
					continue
				}

				if reconnected {
					logger.Infof("[Monitor] Reconnected successfully. Bootstrapping DHT...")
					if err := n.DHT.Bootstrap(ctx); err != nil {
						logger.Warnf("[DHT] Failed to trigger DHT bootstrap on reconnect: %v", err)
					}
					logger.Infof("[Monitor] Reproviding services to DHT...")
					n.services.ReprovideAll(ctx)
					consecutiveFailures = 0
					continue
				}

				consecutiveFailures++
				logger.Errorf("[Monitor] Failed to reconnect to the hub. Consecutive failures: %d/%d", consecutiveFailures, maxFailures)
				if consecutiveFailures >= maxFailures {
					logger.Fatalf("[Monitor] Failed to reconnect to the hub for %d consecutive checks. Exiting to avoid network partition.", maxFailures)
				}
			}
		}
	}()
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
	logger.Infof("[ServiceRegistry] Successfully registered %d static services", len(services))
	return nil
}

func (n *SamNode) ConnectAndAuthWithHub(ctx context.Context, addr multiaddr.Multiaddr) error {
	resolvedAddrs, err := resolveAddrIfNeeded(ctx, addr)
	if err != nil {
		resolvedAddrs = []multiaddr.Multiaddr{addr}
	}

	// Load biscuit from store once before the loop
	biscuitBytes, err := n.Store.LoadIdentity()
	if err != nil {
		return fmt.Errorf("%w: failed to load identity from store: %w", ErrFatalAuth, err)
	}
	if len(biscuitBytes) == 0 {
		return fmt.Errorf("%w: no identity biscuit found in store", ErrFatalAuth)
	}

	var connected bool
	var lastFatalErr error
	var errs []error

	for _, resolved := range resolvedAddrs {
		addrInfo, err := peer.AddrInfoFromP2pAddr(resolved)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get AddrInfo from multiaddr %s: %w", resolved, err))
			continue
		}

		// Create a per-replica timeout context to prevent blocking on offline replicas
		replicaCtx, cancel := context.WithTimeout(ctx, n.config.HubConnectTimeout)

		if err := n.Host.Connect(replicaCtx, *addrInfo); err != nil {
			cancel()
			if strings.Contains(err.Error(), "peer id mismatch") {
				lastFatalErr = fmt.Errorf("%w: %w", ErrFatalAuth, err)
			}
			errs = append(errs, fmt.Errorf("failed to connect to hub %s: %w", resolved, err))
			continue
		}

		// Open auth stream
		s, err := n.Host.NewStream(replicaCtx, addrInfo.ID, api.AuthProtocolID)
		if err != nil {
			cancel()
			errs = append(errs, fmt.Errorf("failed to open auth stream to hub %s: %w", resolved, err))
			continue
		}
		_ = s.SetDeadline(time.Now().Add(5 * time.Second))

		success, err := n.performHubAuthHandshake(s, biscuitBytes, addrInfo.ID)
		if err != nil {
			_ = s.Reset()
			cancel()
			errs = append(errs, fmt.Errorf("handshake failed with hub %s: %w", resolved, err))
			if errors.Is(err, ErrFatalAuth) {
				lastFatalErr = err
			}
			continue
		}
		_ = s.Close()
		cancel()

		if success {
			n.mu.Lock()
			n.authenticatedHubs[addrInfo.ID] = true
			n.HubPeerID = addrInfo.ID
			n.mu.Unlock()
			logger.Infof("[AuthN] Successfully authenticated with hub via libp2p: %s", addrInfo.ID)
			connected = true
		}
	}

	if connected {
		n.authOnce.Do(func() {
			close(n.authSuccess)
		})
		return nil
	}

	if lastFatalErr != nil {
		return lastFatalErr
	}
	return fmt.Errorf("failed to authenticate with any hub addresses: %w", errors.Join(errs...))
}

func (n *SamNode) performHubAuthHandshake(s network.Stream, biscuitBytes []byte, expectedRouter peer.ID) (bool, error) {
	writer := msgio.NewVarintWriter(s)
	authFrame := &api.AuthFrame{Biscuit: biscuitBytes}
	data, err := proto.Marshal(authFrame)
	if err != nil {
		return false, fmt.Errorf("marshal auth frame: %w", err)
	}
	if err := writer.WriteMsg(data); err != nil {
		return false, fmt.Errorf("write auth frame: %w", err)
	}

	reader := msgio.NewVarintReaderSize(s, 1024*64)
	respMsg, err := reader.ReadMsg()
	if err != nil {
		return false, fmt.Errorf("read auth response: %w", err)
	}
	defer reader.ReleaseMsg(respMsg)

	var resp api.AuthResponse
	if err := proto.Unmarshal(respMsg, &resp); err != nil {
		return false, fmt.Errorf("unmarshal auth response: %w", err)
	}

	if !resp.Success {
		return false, fmt.Errorf("%w: auth failed: %s", ErrFatalAuth, resp.Error)
	}

	// Mutual Auth: Verify server/router biscuit
	if len(resp.Biscuit) == 0 {
		return false, fmt.Errorf("%w: remote router returned empty biscuit", ErrFatalAuth)
	}

	n.keysMu.RLock()
	var trustedKeys []ed25519.PublicKey
	for _, tk := range n.trustedKeys {
		trustedKeys = append(trustedKeys, tk.Key)
	}
	n.keysMu.RUnlock()

	if len(trustedKeys) == 0 {
		return false, fmt.Errorf("%w: no trusted control plane keys loaded", ErrFatalAuth)
	}

	// Verify the router's biscuit using the control plane keys
	b, err := identity.VerifyBiscuit(resp.Biscuit, expectedRouter, trustedKeys, n.BiscuitTimeout)
	if err != nil {
		return false, fmt.Errorf("%w: failed to verify router biscuit: %w", ErrFatalAuth, err)
	}

	// Enforce role("router") inside the biscuit
	authorizer, err := b.Authorizer(trustedKeys[0])
	if err != nil {
		return false, fmt.Errorf("authorizer instantiation failed: %w", err)
	}

	authorizer.AddCheck(biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(api.RoleRouter)}},
			},
		},
	}})
	authorizer.AddPolicy(api.AllowIfTruePolicy)

	if err := authorizer.Authorize(); err != nil {
		return false, fmt.Errorf("%w: remote peer lacks router authorization role: %w", ErrFatalAuth, err)
	}

	return true, nil
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
					if renewAfter < 2*time.Second {
						renewAfter = 2 * time.Second
					}
				} else {
					renewAfter = 1 * time.Second
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

				// Try proactive biscuit token refresh first
				refreshErr := n.RefreshEnrollment(ctx)
				if refreshErr == nil {
					logger.Infof("Enrollment renewed successfully via proactive refresh.")
					continue
				}

				logger.Warnw("Proactive biscuit refresh failed, falling back to full OIDC/JWT re-enrollment", "error", refreshErr)

				var newJWT string
				var fetchErr error

				if issuerURL != "" {
					tokenURL, err := n.DiscoverTokenURL(ctx, issuerURL)
					if err != nil {
						fetchErr = fmt.Errorf("failed to discover OIDC endpoints for renewal: %w", err)
					} else {
						newJWT, fetchErr = n.FetchJWT(ctx, tokenURL, clientID, clientSecret)
						if fetchErr != nil {
							fetchErr = fmt.Errorf("failed to fetch JWT for renewal: %w", fetchErr)
						}
					}
				} else if jwtPath != "" {
					data, err := os.ReadFile(jwtPath)
					if err != nil {
						fetchErr = fmt.Errorf("failed to read JWT file for renewal: %w", err)
					} else {
						newJWT = strings.TrimSpace(string(data))
					}
				} else {
					newJWT, fetchErr = n.renewWithRefreshToken(ctx, clientSecret)
				}

				if fetchErr == nil {
					hubURL, loadErr := n.Store.LoadHubURL()
					if loadErr != nil {
						fetchErr = fmt.Errorf("failed to load hub URL for renewal: %w", loadErr)
					} else {
						fetchErr = n.Enroll(ctx, hubURL, newJWT)
					}
				}

				if fetchErr != nil {
					logger.Errorf("Renewal failed: %v", fetchErr)

					// Check if we are already expired and if so, die to avoid a split brain
					exp, loadErr := n.Store.LoadIdentityExpiration()
					if loadErr == nil && exp > 0 {
						if time.Now().After(time.Unix(exp, 0)) {
							logger.Fatalf("Identity expired and renewal failed. Exiting to avoid network partition.")
						}
					}
				} else {
					logger.Infof("Enrollment renewed successfully.")
				}
			}
		}
	}()
}

type RefreshError struct {
	StatusCode int
	Message    string
}

func (e *RefreshError) Error() string {
	return e.Message
}

// RefreshEnrollment trades the expiring biscuit token for a new one using a cryptographic challenge.
func (n *SamNode) RefreshEnrollment(ctx context.Context) error {
	// 1. Fetch current biscuit
	currentBiscuit, err := n.Store.LoadIdentity()
	if err != nil {
		return fmt.Errorf("failed to load current identity: %w", err)
	}

	// 2. Load private key
	privKeyBytes, err := n.Store.LoadKey()
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}
	privKey, err := crypto.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return fmt.Errorf("corrupted private key: %w", err)
	}

	// 3. Generate challenge signature over current timestamp
	timestamp := time.Now().UnixMilli()
	challengeData := []byte(fmt.Sprintf("%d", timestamp))
	sig, err := privKey.Sign(challengeData)
	if err != nil {
		return fmt.Errorf("failed to generate signature: %w", err)
	}

	// 4. Construct request
	req := &api.TokenRefreshRequest{
		ChallengeSignature: sig,
		Timestamp:          timestamp,
	}
	reqData, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	hubURL, err := n.Store.LoadHubURL()
	if err != nil {
		return fmt.Errorf("failed to load hub URL: %w", err)
	}

	if !strings.HasPrefix(hubURL, "http://") && !strings.HasPrefix(hubURL, "https://") {
		return fmt.Errorf("hub address must be an HTTP or HTTPS URL for renewal: %s", hubURL)
	}

	url := hubURL + "/refresh"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqData))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	// Set current biscuit in authorization header
	b64Biscuit := base64.StdEncoding.EncodeToString(currentBiscuit)
	httpReq.Header.Set("Authorization", "Bearer "+b64Biscuit)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusForbidden {
		logger.Errorf("Refresh rejected: Node is banned (403 Forbidden). Initiating hard-kill.")
		if n.Host != nil {
			_ = n.Host.Close()
		}
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &RefreshError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("refresh failed with status %s: %s", resp.Status, string(body)),
		}
	}

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var refreshResp api.TokenRefreshResponse
	if err := proto.Unmarshal(respData, &refreshResp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if refreshResp.ErrorMessage != "" {
		return fmt.Errorf("refresh error: %s", refreshResp.ErrorMessage)
	}

	// Save new biscuit and its expiration
	if err := n.Store.SaveIdentity(refreshResp.BiscuitToken); err != nil {
		return fmt.Errorf("failed to save refreshed identity: %w", err)
	}
	if err := n.Store.SaveIdentityExpiration(refreshResp.ExpiresAt); err != nil {
		return fmt.Errorf("failed to save refreshed expiration: %w", err)
	}

	return nil
}

func (n *SamNode) renewWithRefreshToken(ctx context.Context, clientSecret string) (string, error) {
	if n.Store == nil {
		return "", fmt.Errorf("store is not initialized")
	}

	refreshToken, err := n.Store.LoadRefreshToken()
	if err != nil {
		return "", fmt.Errorf("no refresh token available for renewal: %w", err)
	}

	storedIssuer, storedClientID, _, err := n.Store.LoadOIDCConfig()
	if err != nil {
		return "", fmt.Errorf("failed to load OIDC configuration: %w", err)
	}
	if storedIssuer == "" || storedClientID == "" {
		return "", fmt.Errorf("OIDC configuration is incomplete (issuer or client ID is empty)")
	}

	tokenURL, err := n.DiscoverTokenURL(ctx, storedIssuer)
	if err != nil {
		return "", fmt.Errorf("failed to discover OIDC endpoints for renewal: %w", err)
	}

	newJWT, newRefreshToken, err := n.RefreshJWT(ctx, tokenURL, storedClientID, clientSecret, refreshToken)
	if err != nil {
		return "", fmt.Errorf("failed to refresh JWT: %w", err)
	}

	if newRefreshToken != "" {
		if err := n.Store.SaveRefreshToken(newRefreshToken); err != nil {
			logger.Warnf("Failed to save updated refresh token: %v", err)
		}
	}

	return newJWT, nil
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

	if n.revokedPeers != nil {
		n.revokedPeers.Add(event.PeerId, event.Timestamp)
	}
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
	defer n.mu.Unlock()

	if _, ok := n.topics[topicName]; ok {
		return nil
	}

	topic, err := n.PubSub.Join(topicName)
	if err != nil {
		return err
	}

	sub, err := topic.Subscribe()
	if err != nil {
		return err
	}

	n.topics[topicName] = topic

	logger.Infof("[PubSub] Started subscription background loop for topic: %s", topicName)
	go func() {
		defer func() {
			sub.Cancel()
			logger.Infof("[PubSub] Exited subscription background loop for topic: %s", topicName)
		}()
		for {
			msg, err := sub.Next(context.Background())
			if err != nil {
				logger.Errorf("[PubSub] subscription Next() error for topic %s: %v", topicName, err)
				return
			}
			logger.Debugf("[PubSub] Received message on topic %s from %s: %s", topicName, msg.ReceivedFrom, string(msg.Data))
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

	sem := make(chan struct{}, 8)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			connectedCount := len(n.Host.Network().Peers())
			if connectedCount >= maxMeshProactiveConnections {
				logger.Debugf("[Discovery] Connected peers (%d) >= target (%d). Skipping peer discovery tick.", connectedCount, maxMeshProactiveConnections)
				continue
			}

			peers, err := routingDiscovery.FindPeers(ctx, meshID, discovery.Limit(maxMeshProactiveConnections))
			if err != nil {
				logger.Errorf("[Discovery] Failed to find peers: %v", err)
				continue
			}
			for p := range peers {
				if p.ID == n.Host.ID() {
					continue
				}

				cond := n.Host.Network().Connectedness(p.ID)
				if cond != network.Connected && cond != network.Limited {
					logger.Debugf("[Discovery] Found peer not connected via DHT: %s (state: %s)", p.ID, cond)

					n.Host.Peerstore().AddAddrs(p.ID, p.Addrs, peerstore.TempAddrTTL)
					n.preparePeerAddrs(ctx, p.ID)

					filteredAddrInfo := n.Host.Peerstore().PeerInfo(p.ID)
					if len(filteredAddrInfo.Addrs) == 0 {
						logger.Debugf("[Discovery] Skipping connection to %s: no valid addresses after filtering", p.ID)
						continue
					}

					select {
					case sem <- struct{}{}:
						go func(pi peer.AddrInfo) {
							defer func() { <-sem }()
							dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
							defer cancel()
							if err := n.Host.Connect(dialCtx, pi); err != nil {
								logger.Debugf("[Discovery] Failed to connect to %s: %v", pi.ID, err)
								if putErr := n.Host.Peerstore().Put(pi.ID, PeerstoreKeyPrivateIPFailed, true); putErr != nil {
									logger.Errorf("[Discovery] Failed to put peerstore private IP failed key: %v", putErr)
								}
							}
						}(filteredAddrInfo)
					case <-ctx.Done():
						return
					}
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

	n.keysMu.RLock()
	keys := n.trustedKeys
	n.keysMu.RUnlock()

	var lastErr error
	for _, tk := range keys {
		if len(tk.Key) != ed25519.PublicKeySize {
			continue
		}
		authorizer, err := b.Authorizer(tk.Key, biscuit.WithWorldOptions(
			datalog.WithMaxDuration(5*time.Second),
		))
		if err != nil {
			lastErr = fmt.Errorf("authorizer error: %w", err)
			continue
		}

		authorizer.AddPolicy(api.AllowIfTruePolicy)

		if err := authorizer.Authorize(); err == nil {
			return b, nil
		} else {
			lastErr = fmt.Errorf("authorize error: %w", err)
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("no valid key found (last error: %v)", lastErr)
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
	var errs []error
	if n.DHT != nil {
		if err := n.DHT.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if n.Host != nil {
		if err := n.Host.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (n *SamNode) IsServiceRegistered(serviceName string) bool {
	_, ok := n.services.Get(serviceName)
	return ok
}

// Bound DHT lookups and per-peer catalog fan-out so a partially
// reachable mesh can't wedge a discovery call indefinitely.
const (
	dhtLookupTimeout       = 5 * time.Second
	discoveryFanoutTimeout = 40 * time.Second
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
	limit := n.config.DHTLookupLimit
	if limit <= 0 {
		limit = 20
	}
	for p := range n.DHT.FindProvidersAsync(lookupCtx, c, limit) {
		providersMap[p.ID] = p
	}
	providers := make([]peer.AddrInfo, 0, len(providersMap))
	for _, p := range providersMap {
		hubAddrsCount := 0
		if n.HubPeerID != "" {
			hubAddrsCount = len(n.Host.Peerstore().Addrs(n.HubPeerID))
		}
		logger.Infof("[Discovery] Evaluating relay for %s: HubPeerID=%s, HubAddrsCount=%d", p.ID, n.HubPeerID, hubAddrsCount)

		for _, addr := range p.Addrs {
			logger.Infof("[Discovery] Provider %s advertised address: %s", p.ID, addr)
		}

		if len(p.Addrs) > 0 {
			n.Host.Peerstore().AddAddrs(p.ID, p.Addrs, peerstore.TempAddrTTL)
		}

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
	typeStr, err := api.ServiceTypeToString(serviceType)
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
	typeStr, err := api.ServiceTypeToString(serviceType)
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

		concurrency := n.config.DiscoveryConcurrency
		if concurrency <= 0 {
			concurrency = 10
		}
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for _, p := range peers {
			if p.ID == n.Host.ID() {
				continue
			}
			wg.Add(1)
			go func(peerID peer.ID) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-fanoutCtx.Done():
					return
				}
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
	logger.Infof("[Discovery] FindProvidersByType returned %d peers", len(peers))

	fanoutCtx, cancel := context.WithTimeout(ctx, discoveryFanoutTimeout)
	defer cancel()

	type peerCatalog struct {
		peerID   peer.ID
		services []*api.ServiceInfo
	}
	results := make(chan peerCatalog, len(peers))
	concurrency := n.config.DiscoveryConcurrency
	if concurrency <= 0 {
		concurrency = 10
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, p := range peers {
		if p.ID == n.Host.ID() {
			continue
		}
		wg.Add(1)
		go func(peerID peer.ID) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-fanoutCtx.Done():
				return
			}
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

type readCloserWithCount struct {
	io.ReadCloser
	bytesRead int64
}

func (rc *readCloserWithCount) Read(p []byte) (int, error) {
	n, err := rc.ReadCloser.Read(p)
	rc.bytesRead += int64(n)
	return n, err
}

type responseWriterWithCount struct {
	http.ResponseWriter
	bytesWritten int64
	statusCode   int
}

func (w *responseWriterWithCount) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytesWritten += int64(n)
	return n, err
}

func (w *responseWriterWithCount) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (n *SamNode) StartIngressServer(ctx context.Context) error {
	listener, err := gostream.Listen(n.Host, "/libp2p-http")
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Infof("[Ingress] Received request: %s %s", r.Method, r.URL.Path)
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

			serviceType, err := api.ParseServiceType(serviceTypeStr)
			if err != nil || serviceType == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
				http.Error(w, "Invalid service type", http.StatusBadRequest)
				return
			}

			// Extract biscuit from X-Sam-Biscuit header
			biscuitB64 := r.Header.Get(api.HeaderSamBiscuit)
			if biscuitB64 == "" {
				http.Error(w, "Missing X-Sam-Biscuit header", http.StatusUnauthorized)
				return
			}
			biscuitBytes, err := base64.StdEncoding.DecodeString(biscuitB64)
			if err != nil {
				http.Error(w, "Invalid X-Sam-Biscuit encoding", http.StatusBadRequest)
				return
			}

			// Parse remote peer from RemoteAddr
			remotePeer, err := peer.Decode(r.RemoteAddr)
			if err != nil {
				http.Error(w, "Invalid remote peer", http.StatusBadRequest)
				return
			}

			reqCtx := RequestContext{
				PeerID:   remotePeer,
				User:     "", // Extracted implicitly if needed, or left empty
				Protocol: "/libp2p-http",
				Target:   strings.ToLower(serviceTypeStr) + "://" + serviceName,
			}

			// Verify authorization
			if err := n.VerifyBiscuitToken(biscuitBytes, reqCtx); err != nil {
				logger.Warnf("[Ingress] AuthZ Denied for %s: %v", remotePeer, err)
				http.Error(w, "Authorization failed", http.StatusForbidden)
				return
			}

			// Strip the biscuit header so it doesn't leak to the backend service
			r.Header.Del(api.HeaderSamBiscuit)

			svc, ok := n.services.Get(serviceName)
			if !ok {
				logger.Errorf("[Ingress] Service not found: %s", serviceName)
				http.Error(w, "Service not found", http.StatusNotFound)
				return
			}
			if svc.Handler() == nil {
				logger.Errorf("[Ingress] Service %s has nil handler", serviceName)
				http.Error(w, "Service not found", http.StatusNotFound)
				return
			}
			logger.Infof("[Ingress] Forwarding to service %s, upstreamPath: %q", serviceName, upstreamPath)

			if upstreamPath == "" {
				r.URL.Path = "/"
				if len(parts) == 2 {
					r.Header.Set(api.HeaderSamNoTrailingSlash, "true")
				}
			} else {
				r.URL.Path = "/" + upstreamPath
			}
			r.URL.RawPath = ""

			// Wrap for accounting
			rc := &readCloserWithCount{ReadCloser: r.Body}
			r.Body = rc
			wc := &responseWriterWithCount{ResponseWriter: w, statusCode: http.StatusOK}

			defer func() {
				logger.Infow("Stream Accounting",
					"peer_id", remotePeer.String(),
					"target", reqCtx.Target,
					"protocol", "/libp2p-http",
					"bytes_read", rc.bytesRead,
					"bytes_written", wc.bytesWritten,
				)
			}()

			svc.Handler().ServeHTTP(wc, r)
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
		if proto.Code != multiaddr.P_IP4 && proto.Code != multiaddr.P_IP6 {
			continue
		}
		value, err := addr.ValueForProtocol(proto.Code)
		if err != nil {
			continue
		}
		ip := net.ParseIP(value)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
	}
	return false
}

func isPrivateIP(addr multiaddr.Multiaddr) bool {
	for _, proto := range addr.Protocols() {
		if proto.Code != multiaddr.P_IP4 && proto.Code != multiaddr.P_IP6 {
			continue
		}
		value, err := addr.ValueForProtocol(proto.Code)
		if err != nil {
			continue
		}
		ip := net.ParseIP(value)
		if ip == nil {
			continue
		}
		if ip.IsPrivate() {
			return true
		}
	}
	return false
}

func hasCircuit(addr multiaddr.Multiaddr) bool {
	for _, proto := range addr.Protocols() {
		if proto.Code == multiaddr.P_CIRCUIT {
			return true
		}
	}
	return false
}
