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
