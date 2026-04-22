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
	"strings"
	"time"

	samnet "sam/pkg/net"
	"sam/pkg/protocol"
)

func newAgentDiscoverer(node samnet.Node, federation string, maxDHTCardAge time.Duration) (samnet.AgentDiscoverFunc, error) {
	svc, err := protocol.NewDiscoveryService(node, protocol.WithMaxDHTCardAge(maxDHTCardAge))
	if err != nil {
		return nil, fmt.Errorf("creating discovery service: %w", err)
	}
	return func(ctx context.Context) ([]samnet.DiscoveredAgent, error) {
		seen := map[string]samnet.DiscoveredAgent{}
		const dhtLookupTimeout = 1200 * time.Millisecond

		connectedCtx, cancelConnected := context.WithTimeout(ctx, 2*time.Second)
		connected, err := svc.DiscoverAll(connectedCtx)
		cancelConnected()
		if err == nil {
			for _, card := range connected {
				if record, ok := discoveredAgentFromCard(card); ok {
					seen[record.PeerID] = record
				}
			}
		}

		for _, id := range node.Host().Peerstore().Peers() {
			if id == "" || id == node.PeerID() {
				continue
			}
			lookupCtx, cancelLookup := context.WithTimeout(ctx, dhtLookupTimeout)
			raw, getErr := node.GetValue(lookupCtx, protocol.DHTPeerCardKey(id.String()))
			cancelLookup()
			if getErr != nil {
				continue
			}
			card, decodeErr := decodeAgentCardRaw(raw)
			if decodeErr != nil {
				continue
			}
			if record, ok := discoveredAgentFromCard(card); ok {
				seen[record.PeerID] = record
			}
		}

		for _, id := range node.Host().Network().Peers() {
			lookupCtx, cancelLookup := context.WithTimeout(ctx, dhtLookupTimeout)
			raw, getErr := node.GetValue(lookupCtx, protocol.DHTPeerCardKey(id.String()))
			cancelLookup()
			if getErr != nil {
				continue
			}
			card, decodeErr := decodeAgentCardRaw(raw)
			if decodeErr != nil {
				continue
			}
			if record, ok := discoveredAgentFromCard(card); ok {
				seen[record.PeerID] = record
			}
		}

		capabilities, err := samnet.CachedCapabilities(federation)
		if err == nil {
			for _, capability := range capabilities {
				discoverCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				cards, discoverErr := svc.Discover(discoverCtx, capability)
				cancel()
				if discoverErr != nil {
					continue
				}
				for _, card := range cards {
					if record, ok := discoveredAgentFromCard(card); ok {
						seen[record.PeerID] = record
					}
				}
			}
		}

		out := make([]samnet.DiscoveredAgent, 0, len(seen))
		for _, record := range seen {
			out = append(out, record)
		}
		return out, nil
	}, nil
}

func discoveredAgentFromCard(card *protocol.AgentCard) (samnet.DiscoveredAgent, bool) {
	if card == nil || strings.TrimSpace(card.PeerID) == "" {
		return samnet.DiscoveredAgent{}, false
	}
	raw, err := json.Marshal(card)
	if err != nil {
		return samnet.DiscoveredAgent{}, false
	}
	return samnet.DiscoveredAgent{
		PeerID:       card.PeerID,
		Card:         raw,
		Capabilities: card.CapabilityNames(),
	}, true
}

func decodeCachedAgentCards(federation string) ([]*protocol.AgentCard, error) {
	records, err := samnet.LoadCachedAgentRecords(federation)
	if err != nil {
		return nil, err
	}
	out := make([]*protocol.AgentCard, 0, len(records))
	for _, record := range records {
		card, err := decodeAgentCardRaw(record.Card)
		if err != nil {
			continue
		}
		out = append(out, card)
	}
	return out, nil
}

func upsertAgentCardRecord(federation string, card *protocol.AgentCard) error {
	record, ok := discoveredAgentFromCard(card)
	if !ok {
		return nil
	}
	return samnet.UpsertCachedAgentRecord(federation, record)
}

func decodeAgentCardRaw(raw []byte) (*protocol.AgentCard, error) {
	var card protocol.AgentCard
	if err := json.Unmarshal(raw, &card); err != nil {
		return nil, fmt.Errorf("decoding agent card: %w", err)
	}
	if err := protocol.VerifyAgentCard(&card); err != nil {
		return nil, fmt.Errorf("validating agent card: %w", err)
	}
	return &card, nil
}
