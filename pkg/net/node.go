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

package samnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	coreprotocol "github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/routing"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	relayv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/multiformats/go-multiaddr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var tracer = otel.Tracer("sam/net")

// Compile-time interface assertion.
var _ Node = (*node)(nil)

// node is the concrete implementation of the Node interface.
type node struct {
	opts Options

	mu      sync.RWMutex
	host    host.Host
	kdht    *dht.IpfsDHT
	relay   *relayv2.Relay
	disc    *drouting.RoutingDiscovery
	started bool
	logger  *slog.Logger
}

// New creates a new SAM mesh node. Call Start to initialize networking.
func New(opts ...Option) (Node, error) {
	o := DefaultOptions()
	for _, fn := range opts {
		fn(&o)
	}
	if err := o.validate(); err != nil {
		return nil, fmt.Errorf("invalid node options: %w", err)
	}
	return &node{
		opts:   o,
		logger: o.Logger,
	}, nil
}

// Start initializes the libp2p host with QUIC transport, Kademlia DHT,
// relay v2 client, and DCUtR hole-punching. It connects to bootstrap
// peers and begins DHT participation.
func (n *node) Start(ctx context.Context) error {
	ctx, span := tracer.Start(ctx, "node.Start")
	defer span.End()

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.started {
		return fmt.Errorf("node already started")
	}

	// Build the libp2p host. The Routing callback creates the DHT during
	// host construction, resolving the circular host↔DHT dependency.
	var kdht *dht.IpfsDHT
	h, err := libp2p.New(
		libp2p.Identity(n.opts.PrivateKey),
		libp2p.ListenAddrs(n.opts.ListenAddrs...),
		libp2p.UserAgent(n.opts.UserAgent),
		// QUIC is included in default transports; all QUIC traffic is
		// TLS-encrypted natively, providing zero-knowledge relay semantics.
		libp2p.NATPortMap(),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			var dhtErr error
			kdht, dhtErr = n.newDHT(ctx, h)
			return kdht, dhtErr
		}),
	)
	if err != nil {
		return fmt.Errorf("creating libp2p host: %w", err)
	}

	n.host = h
	n.kdht = kdht

	span.SetAttributes(
		attribute.String("peer_id", h.ID().String()),
		attribute.Int("listen_addrs", len(h.Addrs())),
	)

	// Start relay v2 service if configured, allowing other peers to
	// relay through this node.
	if n.opts.EnableRelayService {
		n.relay, err = relayv2.New(h)
		if err != nil {
			_ = h.Close()
			return fmt.Errorf("starting relay service: %w", err)
		}
		n.logger.Info("relay v2 service enabled")
	}

	// Bootstrap the DHT routing table.
	if err := n.kdht.Bootstrap(ctx); err != nil {
		_ = h.Close()
		return fmt.Errorf("bootstrapping DHT: %w", err)
	}

	// Connect to bootstrap peers concurrently.
	if err := n.connectBootstrapPeers(ctx); err != nil {
		n.logger.Warn("partial bootstrap failure", "error", err)
	}

	// Initialize routing-based discovery backed by the DHT.
	n.disc = drouting.NewRoutingDiscovery(n.kdht)
	n.started = true

	n.logger.Info("node started",
		"peer_id", h.ID(),
		"addrs", h.Addrs(),
	)
	return nil
}

// Stop gracefully shuts down the relay, DHT, and host in order.
func (n *node) Stop(ctx context.Context) error {
	_, span := tracer.Start(ctx, "node.Stop")
	defer span.End()

	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.started {
		return nil
	}

	var errs []error
	if n.relay != nil {
		if err := n.relay.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing relay: %w", err))
		}
	}
	if err := n.kdht.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing DHT: %w", err))
	}
	if err := n.host.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing host: %w", err))
	}

	n.started = false
	n.logger.Info("node stopped")
	return errors.Join(errs...)
}

func (n *node) Host() host.Host {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.host
}

func (n *node) DHT() *dht.IpfsDHT {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.kdht
}

func (n *node) PeerID() peer.ID {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.host == nil {
		return ""
	}
	return n.host.ID()
}

func (n *node) Addrs() []multiaddr.Multiaddr {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.host == nil {
		return nil
	}
	return n.host.Addrs()
}

// Announce advertises a capability to the DHT. The call is synchronous:
// when it returns, the provider record has been stored in the DHT.
func (n *node) Announce(ctx context.Context, capability string) error {
	ctx, span := tracer.Start(ctx, "node.Announce",
		trace.WithAttributes(attribute.String("capability", capability)),
	)
	defer span.End()

	n.mu.RLock()
	disc := n.disc
	n.mu.RUnlock()

	if disc == nil {
		return fmt.Errorf("node not started")
	}

	if _, err := disc.Advertise(ctx, capability); err != nil {
		return fmt.Errorf("advertising capability %q: %w", capability, err)
	}

	n.logger.Info("capability announced", "capability", capability)
	return nil
}

// Discover returns a channel of peers that provide the named capability.
// The channel is closed when the context expires or no more peers are found.
func (n *node) Discover(ctx context.Context, capability string) (<-chan peer.AddrInfo, error) {
	ctx, span := tracer.Start(ctx, "node.Discover",
		trace.WithAttributes(attribute.String("capability", capability)),
	)
	defer span.End()

	n.mu.RLock()
	disc := n.disc
	n.mu.RUnlock()

	if disc == nil {
		return nil, fmt.Errorf("node not started")
	}

	ch, err := disc.FindPeers(ctx, capability)
	if err != nil {
		return nil, fmt.Errorf("discovering capability %q: %w", capability, err)
	}
	return ch, nil
}

// Connect establishes a direct connection to the given peer. libp2p will
// automatically attempt relay and hole-punching for NAT traversal.
func (n *node) Connect(ctx context.Context, pi peer.AddrInfo) error {
	ctx, span := tracer.Start(ctx, "node.Connect",
		trace.WithAttributes(attribute.String("target", pi.ID.String())),
	)
	defer span.End()

	n.mu.RLock()
	h := n.host
	n.mu.RUnlock()

	if h == nil {
		return fmt.Errorf("node not started")
	}

	if err := h.Connect(ctx, pi); err != nil {
		return fmt.Errorf("connecting to %s: %w", pi.ID, err)
	}

	n.logger.Info("connected to peer", "peer_id", pi.ID)
	return nil
}

// newDHT initializes the Kademlia DHT with the configured mode.
// When a FederationID is set, the DHT protocol prefix is scoped to
// "/sam/fed/<id>" so nodes in different federations are mutually invisible.
func (n *node) newDHT(ctx context.Context, h host.Host) (*dht.IpfsDHT, error) {
	prefix := "/sam"
	if n.opts.FederationID != "" {
		prefix = "/sam/fed/" + n.opts.FederationID
	}
	var opts []dht.Option
	opts = append(opts, dht.ProtocolPrefix(coreprotocol.ID(prefix)))
	opts = append(opts, dht.NamespacedValidator("sam", samRecordValidator{}))
	switch n.opts.DHTMode {
	case DHTModeServer:
		opts = append(opts, dht.Mode(dht.ModeServer))
	case DHTModeClient:
		opts = append(opts, dht.Mode(dht.ModeClient))
	default:
		opts = append(opts, dht.Mode(dht.ModeAutoServer))
	}
	return dht.New(ctx, h, opts...)
}

// PutValue stores opaque bytes in the DHT under a namespaced key.
func (n *node) PutValue(ctx context.Context, key string, value []byte) error {
	ctx, span := tracer.Start(ctx, "node.PutValue",
		trace.WithAttributes(attribute.String("key", key)),
	)
	defer span.End()

	n.mu.RLock()
	k := n.kdht
	n.mu.RUnlock()

	if k == nil {
		return fmt.Errorf("node not started")
	}
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("key is required")
	}
	if len(value) == 0 {
		return fmt.Errorf("value is required")
	}
	if !strings.HasPrefix(key, "/") {
		key = "/" + key
	}
	if err := k.PutValue(ctx, key, value); err != nil {
		return fmt.Errorf("put DHT value for %q: %w", key, err)
	}
	return nil
}

// GetValue fetches bytes from the DHT using a namespaced key.
func (n *node) GetValue(ctx context.Context, key string) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "node.GetValue",
		trace.WithAttributes(attribute.String("key", key)),
	)
	defer span.End()

	n.mu.RLock()
	k := n.kdht
	n.mu.RUnlock()

	if k == nil {
		return nil, fmt.Errorf("node not started")
	}
	if strings.TrimSpace(key) == "" {
		return nil, fmt.Errorf("key is required")
	}
	if !strings.HasPrefix(key, "/") {
		key = "/" + key
	}
	value, err := k.GetValue(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("get DHT value for %q: %w", key, err)
	}
	return value, nil
}

type samRecordValidator struct{}

func (samRecordValidator) Validate(_ string, value []byte) error {
	if len(value) == 0 {
		return fmt.Errorf("empty SAM record")
	}
	return nil
}

func (samRecordValidator) Select(_ string, values [][]byte) (int, error) {
	if len(values) == 0 {
		return -1, fmt.Errorf("no SAM records")
	}

	best := 0
	bestIssuedAt := parseIssuedAt(values[0])
	for i := 1; i < len(values); i++ {
		issuedAt := parseIssuedAt(values[i])
		if issuedAt.After(bestIssuedAt) {
			best = i
			bestIssuedAt = issuedAt
		}
	}
	return best, nil
}

func parseIssuedAt(value []byte) time.Time {
	var payload struct {
		IssuedAt time.Time `json:"issued_at"`
	}
	if err := json.Unmarshal(value, &payload); err != nil {
		return time.Time{}
	}
	return payload.IssuedAt
}

// connectBootstrapPeers connects to all configured bootstrap peers concurrently.
func (n *node) connectBootstrapPeers(ctx context.Context) error {
	if len(n.opts.BootstrapPeers) == 0 {
		return nil
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)

	for _, addr := range n.opts.BootstrapPeers {
		pi, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("parsing bootstrap addr %s: %w", addr, err))
			mu.Unlock()
			continue
		}

		wg.Add(1)
		go func(pi peer.AddrInfo) {
			defer wg.Done()
			if err := n.host.Connect(ctx, pi); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("bootstrap peer %s: %w", pi.ID, err))
				mu.Unlock()
				return
			}
			n.logger.Debug("bootstrap peer connected", "peer_id", pi.ID)
		}(*pi)
	}

	wg.Wait()
	return errors.Join(errs...)
}
