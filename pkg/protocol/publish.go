package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
)

// DHTPublisher is the subset of SAM networking used to advertise cards.
type DHTPublisher interface {
	Announce(ctx context.Context, capability string) error
	PutValue(ctx context.Context, key string, value []byte) error
	PeerID() peer.ID
}

// Publisher signs and publishes AgentCards into capability-scoped DHT namespaces.
type Publisher struct {
	net DHTPublisher
}

// NewPublisher creates an AgentCard publisher bound to a mesh node.
func NewPublisher(net DHTPublisher) (*Publisher, error) {
	if net == nil {
		return nil, fmt.Errorf("publisher network is nil")
	}
	if net.PeerID() == "" {
		return nil, fmt.Errorf("publisher network peer ID is empty")
	}
	return &Publisher{net: net}, nil
}

// Publish verifies and announces the card under the SAM agent namespace.
//
// Each capability is announced under:
//
//	/sam/v1/agents/capability/<capability>
//
// and the card identity itself is announced under:
//
//	/sam/v1/agents/peer/<peerID>
func (p *Publisher) Publish(ctx context.Context, card *AgentCard) error {
	if card == nil {
		return fmt.Errorf("agent card is nil")
	}
	if err := VerifyAgentCard(card); err != nil {
		return fmt.Errorf("validating card before publish: %w", err)
	}

	nodePeerID := p.net.PeerID().String()
	if nodePeerID != card.PeerID {
		return fmt.Errorf("card peer ID %q does not match node peer ID %q", card.PeerID, nodePeerID)
	}

	peerNS := AgentPeerNamespace(card.PeerID)
	if err := p.net.Announce(ctx, peerNS); err != nil {
		return fmt.Errorf("announcing peer namespace %q: %w", peerNS, err)
	}

	payload, err := json.Marshal(card)
	if err != nil {
		return fmt.Errorf("encoding card payload: %w", err)
	}
	if err := p.net.PutValue(ctx, DHTPeerCardKey(card.PeerID), payload); err != nil {
		return fmt.Errorf("publishing peer card key for %q: %w", card.PeerID, err)
	}

	for _, capability := range card.CapabilityNames() {
		ns := AgentCapabilityNamespace(capability)
		if err := p.net.Announce(ctx, ns); err != nil {
			return fmt.Errorf("announcing capability namespace %q: %w", ns, err)
		}
		if err := p.net.PutValue(ctx, DHTCapabilityCardKey(capability, card.PeerID), payload); err != nil {
			return fmt.Errorf("publishing capability card key for %q: %w", capability, err)
		}
	}

	return nil
}

// AgentCapabilityNamespace returns the capability-scoped DHT namespace key.
func AgentCapabilityNamespace(capability string) string {
	capability = strings.ToLower(strings.TrimSpace(capability))
	capability = strings.ReplaceAll(capability, " ", "-")
	return AgentDHTNamespaceBase + "capability/" + capability
}

// AgentPeerNamespace returns the peer-scoped DHT namespace key.
func AgentPeerNamespace(peerID string) string {
	return AgentDHTNamespaceBase + "peer/" + strings.TrimSpace(peerID)
}

// DHTCapabilityCardKey is the DHT value key for a capability and peer card.
func DHTCapabilityCardKey(capability, peerID string) string {
	capability = strings.ToLower(strings.TrimSpace(capability))
	capability = strings.ReplaceAll(capability, " ", "-")
	peerID = strings.TrimSpace(peerID)
	return "/sam/capability/" + capability + "/" + peerID
}

// DHTPeerCardKey is the DHT value key for a peer's latest signed AgentCard.
func DHTPeerCardKey(peerID string) string {
	return "/sam/peer/" + strings.TrimSpace(peerID) + "/agent-card"
}
