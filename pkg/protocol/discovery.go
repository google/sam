package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	samnet "sam/pkg/net"
)

const (
	AgentCardProtocolID = "/sam/agentcard/1.0"
	// maxDHTCardAge bounds how old a DHT card can be before we prefer a direct
	// stream fetch from the peer.
	maxDHTCardAge = 15 * time.Minute
)

type cardFetchSource int

const (
	cardFromDHT cardFetchSource = iota
	cardFromStream
)

// DiscoveryService discovers and validates AgentCards over DHT and libp2p.
type DiscoveryService struct {
	node samnet.Node
	// maxDHTCardAge bounds accepted DHT card freshness.
	// When <= 0, freshness checks are disabled.
	maxDHTCardAge time.Duration

	mu        sync.RWMutex
	localCard *AgentCard
}

// DiscoveryOption configures DiscoveryService behavior.
type DiscoveryOption func(*DiscoveryService) error

// WithMaxDHTCardAge sets the freshness bound for DHT-fetched cards.
// A value <= 0 disables freshness checks.
func WithMaxDHTCardAge(maxAge time.Duration) DiscoveryOption {
	return func(s *DiscoveryService) error {
		s.maxDHTCardAge = maxAge
		return nil
	}
}

// NewDiscoveryService creates a discovery service backed by a SAM node.
func NewDiscoveryService(node samnet.Node, opts ...DiscoveryOption) (*DiscoveryService, error) {
	if node == nil {
		return nil, fmt.Errorf("node is nil")
	}
	if node.Host() == nil {
		return nil, fmt.Errorf("node host is nil")
	}

	s := &DiscoveryService{
		node:          node,
		maxDHTCardAge: maxDHTCardAge,
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, fmt.Errorf("applying discovery option: %w", err)
		}
	}
	return s, nil
}

// RegisterLocalCard stores the local card and serves it over AgentCardProtocolID.
func (s *DiscoveryService) RegisterLocalCard(card *AgentCard) error {
	if card == nil {
		return fmt.Errorf("local card is nil")
	}
	if err := VerifyAgentCard(card); err != nil {
		return fmt.Errorf("invalid local card: %w", err)
	}
	if card.PeerID != s.node.PeerID().String() {
		return fmt.Errorf("local card peer ID %q does not match node peer ID %q", card.PeerID, s.node.PeerID())
	}

	s.mu.Lock()
	s.localCard = card
	s.mu.Unlock()

	s.node.Host().SetStreamHandler(AgentCardProtocolID, s.handleAgentCardStream)
	return nil
}

// Discover resolves providers for a capability namespace and returns verified cards.
func (s *DiscoveryService) Discover(ctx context.Context, capability string) ([]*AgentCard, error) {
	peers, err := s.DiscoverPeers(ctx, capability)
	if err != nil {
		return nil, err
	}

	cards := make([]*AgentCard, 0)
	for _, pi := range peers {
		card, src, err := s.fetchCard(ctx, pi)
		if err != nil {
			continue
		}
		if !hasCapability(card, capability) && src == cardFromDHT {
			// DHT can lag behind recent card updates; retry over direct stream.
			streamCard, streamErr := s.fetchCardFromStream(ctx, pi)
			if streamErr == nil && hasCapability(streamCard, capability) {
				card = streamCard
			} else {
				continue
			}
		}
		cards = append(cards, card)
	}

	return cards, nil
}

// DiscoverPeers resolves providers for a capability namespace and returns
// unique peer addresses suitable for direct libp2p connection attempts.
func (s *DiscoveryService) DiscoverPeers(ctx context.Context, capability string) ([]peer.AddrInfo, error) {
	capNS := AgentCapabilityNamespace(capability)
	ch, err := s.node.Discover(ctx, capNS)
	if err != nil {
		return nil, fmt.Errorf("discovering namespace %q: %w", capNS, err)
	}

	seen := map[string]struct{}{}
	peers := make([]peer.AddrInfo, 0)
	localPeerID := s.node.PeerID()

	for pi := range ch {
		if pi.ID == "" || pi.ID == localPeerID {
			continue
		}
		if _, ok := seen[pi.ID.String()]; ok {
			continue
		}
		seen[pi.ID.String()] = struct{}{}
		peers = append(peers, pi)
	}

	return peers, nil
}

// DiscoverPeerIDs returns unique peer IDs for a capability using DHT-only lookup.
func (s *DiscoveryService) DiscoverPeerIDs(ctx context.Context, capability string) ([]peer.ID, error) {
	peers, err := s.DiscoverPeers(ctx, capability)
	if err != nil {
		return nil, err
	}
	ids := make([]peer.ID, 0, len(peers))
	for _, pi := range peers {
		ids = append(ids, pi.ID)
	}
	return ids, nil
}

// ConnectPeers attempts direct connection to every discovered peer. libp2p
// handles NAT traversal via relay and DCUtR hole-punching internally.
func (s *DiscoveryService) ConnectPeers(ctx context.Context, peers []peer.AddrInfo) ([]peer.ID, error) {
	connected := make([]peer.ID, 0, len(peers))
	var errs []error

	for _, pi := range peers {
		if pi.ID == "" {
			continue
		}
		if err := s.node.Connect(ctx, pi); err != nil {
			errs = append(errs, fmt.Errorf("connecting to %s: %w", pi.ID, err))
			continue
		}
		connected = append(connected, pi.ID)
	}

	return connected, errors.Join(errs...)
}

// DiscoverAll fetches AgentCards from every peer the local node is currently
// connected to that speaks AgentCardProtocolID. It is suitable for listing
// all known agents without filtering by capability.
func (s *DiscoveryService) DiscoverAll(ctx context.Context) ([]*AgentCard, error) {
	peers := s.node.Host().Network().Peers()
	cards := make([]*AgentCard, 0, len(peers))
	for _, id := range peers {
		addrs := s.node.Host().Peerstore().Addrs(id)
		pi := peer.AddrInfo{ID: id, Addrs: addrs}
		card, _, err := s.fetchCard(ctx, pi)
		if err != nil {
			continue
		}
		cards = append(cards, card)
	}
	return cards, nil
}

// DiscoverAndConnect discovers peers for a capability and directly connects to
// each one before task execution begins.
func (s *DiscoveryService) DiscoverAndConnect(ctx context.Context, capability string) ([]peer.ID, error) {
	peers, err := s.DiscoverPeers(ctx, capability)
	if err != nil {
		return nil, err
	}
	return s.ConnectPeers(ctx, peers)
}

func (s *DiscoveryService) fetchCard(ctx context.Context, pi peer.AddrInfo) (*AgentCard, cardFetchSource, error) {
	card, err := s.fetchCardFromDHT(ctx, pi.ID.String())
	if err == nil {
		return card, cardFromDHT, nil
	}

	card, err = s.fetchCardFromStream(ctx, pi)
	if err != nil {
		return nil, cardFromStream, err
	}
	return card, cardFromStream, nil
}

func (s *DiscoveryService) fetchCardFromDHT(ctx context.Context, peerID string) (*AgentCard, error) {
	key := DHTPeerCardKey(peerID)
	raw, err := s.node.GetValue(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("reading DHT card key %q: %w", key, err)
	}

	var card AgentCard
	if err := json.Unmarshal(raw, &card); err != nil {
		return nil, fmt.Errorf("decoding DHT card for %s: %w", peerID, err)
	}
	if err := VerifyAgentCard(&card); err != nil {
		return nil, fmt.Errorf("validating DHT card for %s: %w", peerID, err)
	}
	if card.PeerID != peerID {
		return nil, fmt.Errorf("DHT card peer ID %q mismatch for key peer %q", card.PeerID, peerID)
	}
	if s.maxDHTCardAge > 0 && time.Since(card.IssuedAt) > s.maxDHTCardAge {
		return nil, fmt.Errorf("DHT card for %s is stale", peerID)
	}
	return &card, nil
}

func (s *DiscoveryService) fetchCardFromStream(ctx context.Context, pi peer.AddrInfo) (*AgentCard, error) {
	if err := s.node.Connect(ctx, pi); err != nil {
		return nil, fmt.Errorf("connecting to peer %s: %w", pi.ID, err)
	}

	stream, err := s.node.Host().NewStream(ctx, pi.ID, AgentCardProtocolID)
	if err != nil {
		return nil, fmt.Errorf("opening card stream to %s: %w", pi.ID, err)
	}
	defer func() { _ = stream.Close() }()

	var card AgentCard
	if err := json.NewDecoder(stream).Decode(&card); err != nil {
		return nil, fmt.Errorf("decoding agent card from %s: %w", pi.ID, err)
	}
	if err := VerifyAgentCard(&card); err != nil {
		return nil, fmt.Errorf("validating stream card from %s: %w", pi.ID, err)
	}
	if card.PeerID != pi.ID.String() {
		return nil, fmt.Errorf("stream card peer ID %q mismatch for peer %q", card.PeerID, pi.ID)
	}
	return &card, nil
}

func (s *DiscoveryService) handleAgentCardStream(stream network.Stream) {
	defer func() { _ = stream.Close() }()

	s.mu.RLock()
	card := s.localCard
	s.mu.RUnlock()

	if card == nil {
		_, _ = io.WriteString(stream, `{"error":"agent card not registered"}`)
		return
	}
	if err := json.NewEncoder(stream).Encode(card); err != nil {
		_ = stream.Reset()
	}
}

func hasCapability(card *AgentCard, capability string) bool {
	want := AgentCapabilityNamespace(capability)
	for _, c := range card.CapabilityNames() {
		if AgentCapabilityNamespace(c) == want {
			return true
		}
	}
	return false
}
