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
	"context"
	"crypto/ed25519"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"
)

// parseRequiredLabels splits the X-Sam-Required-Labels header value
// (comma-separated "key=value" pairs) into a label map; any malformed entry
// rejects the whole request.
//
// Only a blank specification means "no requirement". A specification that
// carries content but names no label — ",," or a lone separator — is rejected
// instead of being read as unconstrained: an empty requirement set switches
// the label gate off entirely (see VerifyPeerLabels and rankProviders), so
// silently deriving one from a caller's non-blank input would turn a
// fail-closed control into a fail-open one. Empty entries *alongside* real
// ones stay tolerated, so a trailing comma is still harmless.
func parseRequiredLabels(h string) (map[string]string, error) {
	if strings.TrimSpace(h) == "" {
		return nil, nil
	}
	var out map[string]string
	for _, part := range strings.Split(h, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("invalid label %q: expected key=value", part)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if err := api.ValidateLabelKey(k); err != nil {
			return nil, err
		}
		if err := api.ValidateLabelValue(v); err != nil {
			return nil, err
		}
		if out == nil {
			out = make(map[string]string)
		}
		if _, exists := out[k]; exists {
			return nil, fmt.Errorf("duplicate label key %q", k)
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("invalid required labels %q: expected at least one key=value pair", h)
	}
	return out, nil
}

// The label gate is the consumer-side enforcement point for label
// requirements: gossip labels only rank providers, this gate verifies the
// provider's control-plane-attested label() facts (api.FactLabel) before
// any request data leaves this node. Fail-closed: a provider that returns no
// biscuit or lacks a matching fact is rejected.
const (
	labelGateCacheSize = 1024
	// labelGateTTL bounds how long a positive verification verdict is
	// reused before the provider's biscuit is fetched and checked again.
	labelGateTTL = 5 * time.Minute
	// labelGateDialTimeout bounds the biscuit-fetch handshake.
	labelGateDialTimeout = 10 * time.Second
)

// labelGateKey builds a deterministic cache key from a required label set and
// the floor in force. The floor is part of the key because a verdict reached
// under one floor says nothing about another: keying on the caller's
// requirement alone would let a cached pass survive a configuration change.
//
// The encoding is unambiguous, and it is worth saying why, because the
// separators are ordinary printable characters that a label value is allowed
// to contain. What rules a collision out is that "=" is not: every entry is
// "|<key>=<value>", ValidateLabelKey admits only [a-zA-Z0-9_.-] so a key
// cannot hold a separator, and ValidateLabelValue rejects "=" so a value
// cannot forge the "|<key>=" that starts an entry. A value may therefore
// contain "|" or "#floor" freely without shifting where any boundary falls,
// and no pair of distinct (required, floor) inputs can render the same string.
func labelGateKey(peerID peer.ID, required, floor map[string]string) string {
	render := func(sb *strings.Builder, m map[string]string) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sb.WriteByte('|')
			sb.WriteString(k)
			sb.WriteByte('=')
			sb.WriteString(m[k])
		}
	}
	var sb strings.Builder
	sb.WriteString(peerID.String())
	render(&sb, required)
	sb.WriteString("#floor")
	render(&sb, floor)
	return sb.String()
}

// egressFloor returns the operator's egress floor, or nil when none is
// configured (api.Egress.RequireLabels).
func (n *SamNode) egressFloor() map[string]string {
	// Nil-safe for the same reason labels() is: NewSamNode always leaves
	// nodeConfig set, but tests build SamNode directly.
	if n.nodeConfig == nil {
		return nil
	}
	return n.nodeConfig.EgressRequireLabels
}

// VerifyPeerLabels ensures the peer holds control-plane-attested labels
// satisfying the caller's requirement (any one pair) and the operator's egress
// floor (every pair). Positive verdicts are cached.
//
// The gate runs whenever either exists. A caller that requires nothing is
// still held to the floor — the whole point of a floor is that the party being
// constrained does not get to opt out of it by saying nothing.
func (n *SamNode) VerifyPeerLabels(ctx context.Context, peerID peer.ID, required map[string]string) error {
	floor := n.egressFloor()
	if len(required) == 0 && len(floor) == 0 {
		return nil
	}
	key := labelGateKey(peerID, required, floor)
	if until, ok := n.peerLabelGate.Get(key); ok && time.Now().Before(until) {
		return nil
	}

	providerBiscuit, err := n.fetchPeerBiscuit(ctx, peerID)
	if err != nil {
		return fmt.Errorf("provider %s labels unverifiable: %w", peerID, err)
	}
	if err := n.checkPeerLabels(providerBiscuit, peerID, required); err != nil {
		return err
	}

	n.peerLabelGate.Add(key, time.Now().Add(labelGateTTL))
	return nil
}

// checkPeerLabels verifies the provider's biscuit (control-plane signature,
// expiry, binding to peerID) and evaluates the caller's requirement and the
// operator's egress floor against its attested facts.
func (n *SamNode) checkPeerLabels(providerBiscuit []byte, peerID peer.ID, required map[string]string) error {
	floor := n.egressFloor()
	if len(providerBiscuit) == 0 {
		return fmt.Errorf("provider %s returned no identity biscuit; cannot attest required labels %v (egress floor %v)", peerID, required, floor)
	}

	n.keysMu.RLock()
	trustedKeys := make([]ed25519.PublicKey, 0, len(n.trustedKeys))
	for _, tk := range n.trustedKeys {
		trustedKeys = append(trustedKeys, tk.Key)
	}
	n.keysMu.RUnlock()
	if len(trustedKeys) == 0 {
		return fmt.Errorf("no trusted control plane keys loaded")
	}

	b, key, err := identity.VerifyBiscuitAndGetKey(providerBiscuit, peerID, trustedKeys, n.BiscuitTimeout)
	if err != nil {
		return fmt.Errorf("provider %s biscuit verification failed: %w", peerID, err)
	}

	authorizer, err := b.Authorizer(key, identity.AuthorizerOptions(n.BiscuitTimeout)...)
	if err != nil {
		return fmt.Errorf("provider %s authorizer instantiation failed: %w", peerID, err)
	}
	// Two checks, not one merged set. The authorizer ANDs them, so the peer
	// has to satisfy both independently; merging them into a single
	// disjunction would let the caller's pairs stand in for the floor's and
	// widen exactly what the floor exists to bound.
	if len(required) > 0 {
		check, err := api.LabelCheck(required)
		if err != nil {
			return err
		}
		authorizer.AddCheck(check)
	}
	if len(floor) > 0 {
		check, err := api.LabelFloorCheck(floor)
		if err != nil {
			return err
		}
		authorizer.AddCheck(check)
	}
	authorizer.AddPolicy(api.AllowIfTruePolicy)
	if err := authorizer.Authorize(); err != nil {
		if len(floor) > 0 {
			return fmt.Errorf("provider %s does not attest the caller requirement %v and the egress floor %v: %w", peerID, required, floor, err)
		}
		return fmt.Errorf("provider %s has no attested label matching %v: %w", peerID, required, err)
	}
	return nil
}

// fetchPeerBiscuit obtains the peer's control-plane-minted identity via the
// mutual auth handshake on AuthProtocolID, authenticating with our own.
func (n *SamNode) fetchPeerBiscuit(ctx context.Context, peerID peer.ID) ([]byte, error) {
	observation, err := n.fetchPeerBiscuitEvidence(ctx, peerID)
	if err != nil {
		return nil, err
	}
	return observation.Biscuit, nil
}

type peerBiscuitObservation struct {
	Biscuit        []byte
	ConnectionPeer peer.ID
}

// fetchPeerBiscuitEvidence is the uncached form used by the local evidence API.
// It preserves the PeerID authenticated by the libp2p stream separately from
// the requested target so callers can fail closed on any binding mismatch.
func (n *SamNode) fetchPeerBiscuitEvidence(ctx context.Context, peerID peer.ID) (peerBiscuitObservation, error) {
	ourBiscuit := n.GetIdentity()
	if ourBiscuit == nil {
		return peerBiscuitObservation{}, fmt.Errorf("missing node identity")
	}

	dialCtx, cancel := context.WithTimeout(ctx, labelGateDialTimeout)
	defer cancel()
	s, err := n.Host.NewStream(dialCtx, peerID, api.AuthProtocolID)
	if err != nil {
		return peerBiscuitObservation{}, fmt.Errorf("failed to open auth stream: %w", err)
	}
	defer func() { _ = s.Close() }()
	_ = s.SetDeadline(time.Now().Add(labelGateDialTimeout))
	connectionPeer := s.Conn().RemotePeer()
	if connectionPeer != peerID {
		return peerBiscuitObservation{}, fmt.Errorf("authenticated connection peer %s does not match requested peer %s", connectionPeer, peerID)
	}

	authBytes, err := proto.Marshal(&api.AuthFrame{Biscuit: ourBiscuit})
	if err != nil {
		return peerBiscuitObservation{}, fmt.Errorf("marshal auth frame: %w", err)
	}
	writer := msgio.NewVarintWriter(s)
	if err := writer.WriteMsg(authBytes); err != nil {
		return peerBiscuitObservation{}, fmt.Errorf("write auth frame: %w", err)
	}

	reader := msgio.NewVarintReaderSize(s, 1024*64)
	msg, err := reader.ReadMsg()
	if err != nil {
		return peerBiscuitObservation{}, fmt.Errorf("read auth response (peer may predate mutual auth): %w", err)
	}
	defer reader.ReleaseMsg(msg)

	var resp api.AuthResponse
	if err := proto.Unmarshal(msg, &resp); err != nil {
		return peerBiscuitObservation{}, fmt.Errorf("invalid auth response: %w", err)
	}
	if !resp.Success {
		return peerBiscuitObservation{}, fmt.Errorf("auth rejected: %s", resp.Error)
	}
	return peerBiscuitObservation{
		Biscuit:        resp.Biscuit,
		ConnectionPeer: connectionPeer,
	}, nil
}
