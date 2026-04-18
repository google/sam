package protocol

import (
	"fmt"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

// ToA2ACard converts a SAM AgentCard to the official A2A SDK representation.
//
// interfaceURL should point to the remote endpoint where this agent accepts
// A2A requests. It is used to populate AgentCard.SupportedInterfaces.
func (c *AgentCard) ToA2ACard(interfaceURL string) (*a2a.AgentCard, error) {
	if c == nil {
		return nil, fmt.Errorf("agent card is nil")
	}
	if err := c.validateBase(); err != nil {
		return nil, err
	}
	out := normalizeA2ACard(c.AgentCard)
	if strings.TrimSpace(interfaceURL) != "" {
		out.SupportedInterfaces = []*a2a.AgentInterface{
			a2a.NewAgentInterface(interfaceURL, a2a.TransportProtocolJSONRPC),
		}
	}
	return &out, nil
}

// AgentCardFromA2A converts an A2A SDK AgentCard into the local SAM AgentCard.
//
// peerID must be provided by the SAM node identity layer and becomes the
// signature identity for the resulting card.
func AgentCardFromA2A(peerID string, card *a2a.AgentCard, resources []MCPResource) (*AgentCard, error) {
	if card == nil {
		return nil, fmt.Errorf("a2a agent card is nil")
	}
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return nil, fmt.Errorf("peer ID is required")
	}

	capabilities := make([]string, 0, len(card.Skills))
	for _, skill := range card.Skills {
		if strings.TrimSpace(skill.ID) != "" {
			capabilities = append(capabilities, skill.ID)
			continue
		}
		if strings.TrimSpace(skill.Name) != "" {
			capabilities = append(capabilities, skill.Name)
		}
	}

	out := &AgentCard{
		AgentCard: normalizeA2ACard(*card),
		PeerID:    peerID,
		Resources: normalizeResources(resources),
		Algorithm: AgentCardSignAlgo,
	}
	if len(capabilities) == 0 {
		return nil, fmt.Errorf("a2a card must contain at least one skill")
	}
	return out, nil
}
