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
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestCheckPeerLabels(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = otherPub

	providerPeer := peer.ID("provider-peer-id")
	expiry := time.Now().Add(time.Hour)

	mint := func(key ed25519.PrivateKey, p peer.ID, labels map[string]string) []byte {
		t.Helper()
		b, err := identity.MintBootstrapBiscuitToken(key, p, api.RoleNode, expiry, nil, labels)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		return b
	}

	node := &SamNode{
		trustedKeys:    []TrustedKey{{Key: cpPub, ReceivedAt: time.Now()}},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	tests := []struct {
		name      string
		biscuit   []byte
		required  map[string]string
		expectErr bool
	}{
		{"exact match", mint(cpPriv, providerPeer, map[string]string{"region": "us-east-1"}), map[string]string{"region": "us-east-1"}, false},
		{"any-of requirement matches one key", mint(cpPriv, providerPeer, map[string]string{"region": "na-us", "team": "platform"}), map[string]string{"region": "eu", "team": "platform"}, false},
		{"no built-in hierarchy: coarser requirement fails a finer claim", mint(cpPriv, providerPeer, map[string]string{"region": "us-east-1"}), map[string]string{"region": "us"}, true},
		{"disjoint labels fail", mint(cpPriv, providerPeer, map[string]string{"region": "na-us"}), map[string]string{"region": "eu"}, true},
		{"unattested token fails closed", mint(cpPriv, providerPeer, nil), map[string]string{"region": "eu"}, true},
		{"empty biscuit fails closed", nil, map[string]string{"region": "eu"}, true},
		{"untrusted signer fails", mint(otherPriv, providerPeer, map[string]string{"region": "eu"}), map[string]string{"region": "eu"}, true},
		{"token bound to another peer fails", mint(cpPriv, peer.ID("other-peer"), map[string]string{"region": "eu"}), map[string]string{"region": "eu"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := node.checkPeerLabels(tt.biscuit, providerPeer, tt.required)
			if tt.expectErr && err == nil {
				t.Error("expected error, got nil")
			} else if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}

	t.Run("no trusted keys fails closed", func(t *testing.T) {
		bare := &SamNode{BiscuitTimeout: 500 * time.Millisecond}
		if err := bare.checkPeerLabels(mint(cpPriv, providerPeer, map[string]string{"region": "eu"}), providerPeer, map[string]string{"region": "eu"}); err == nil {
			t.Error("expected error, got nil")
		}
	})
}

// The egress floor is the operator's, and a caller cannot waive it by asking
// for nothing or by asking for something else. It is ANDed with the caller's
// requirement, so both hold independently: the caller may narrow the choice of
// provider, never widen it past the floor.
func TestCheckPeerLabelsEnforcesEgressFloor(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	providerPeer := peer.ID("provider-peer-id")
	expiry := time.Now().Add(time.Hour)

	mint := func(labels map[string]string) []byte {
		t.Helper()
		b, err := identity.MintBootstrapBiscuitToken(cpPriv, providerPeer, api.RoleNode, expiry, nil, labels)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		return b
	}

	nodeWithFloor := func(floor map[string]string) *SamNode {
		return &SamNode{
			trustedKeys:    []TrustedKey{{Key: cpPub, ReceivedAt: time.Now()}},
			BiscuitTimeout: 500 * time.Millisecond,
			nodeConfig:     &NodeConfigComplete{EgressRequireLabels: floor},
		}
	}

	euGdpr := map[string]string{"jurisdiction": "eu", "compliance": "gdpr"}

	tests := []struct {
		name      string
		floor     map[string]string
		required  map[string]string
		attested  map[string]string
		expectErr bool
	}{{
		name:     "caller requires nothing but the floor still applies",
		floor:    map[string]string{"jurisdiction": "eu"},
		required: nil,
		attested: map[string]string{"jurisdiction": "eu"},
	}, {
		name:      "caller requires nothing and the provider is outside the floor",
		floor:     map[string]string{"jurisdiction": "eu"},
		required:  nil,
		attested:  map[string]string{"jurisdiction": "us"},
		expectErr: true,
	}, {
		name:      "the floor is a conjunction: one pair short is not enough",
		floor:     euGdpr,
		required:  nil,
		attested:  map[string]string{"jurisdiction": "eu"},
		expectErr: true,
	}, {
		name:     "the floor is satisfied when every pair is attested",
		floor:    euGdpr,
		required: nil,
		attested: map[string]string{"jurisdiction": "eu", "compliance": "gdpr", "region": "de"},
	}, {
		// The whole reason the two are separate checks. Merged into one
		// disjunction, region=us-east-1 alone would satisfy it.
		name:      "a caller cannot widen the floor by naming another label",
		floor:     map[string]string{"jurisdiction": "eu"},
		required:  map[string]string{"region": "us-east-1"},
		attested:  map[string]string{"jurisdiction": "us", "region": "us-east-1"},
		expectErr: true,
	}, {
		name:     "caller and floor both satisfied",
		floor:    map[string]string{"jurisdiction": "eu"},
		required: map[string]string{"region": "de-txl"},
		attested: map[string]string{"jurisdiction": "eu", "region": "de-txl"},
	}, {
		name:      "caller narrows within the floor and the provider misses the narrowing",
		floor:     map[string]string{"jurisdiction": "eu"},
		required:  map[string]string{"region": "de-txl"},
		attested:  map[string]string{"jurisdiction": "eu", "region": "fr-par"},
		expectErr: true,
	}, {
		name:      "no floor configured leaves the caller's requirement alone",
		floor:     nil,
		required:  map[string]string{"region": "eu"},
		attested:  map[string]string{"region": "eu"},
		expectErr: false,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := nodeWithFloor(tt.floor).checkPeerLabels(mint(tt.attested), providerPeer, tt.required)
			if tt.expectErr && err == nil {
				t.Errorf("expected rejection, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("expected acceptance, got %v", err)
			}
		})
	}
}

// VerifyPeerLabels short-circuits when there is nothing to check. With a floor
// configured there always is, so the short-circuit must not swallow it: the
// gate has to run even for a caller that asked for nothing, which is the
// difference between a floor and a suggestion.
func TestVerifyPeerLabelsDoesNotShortCircuitPastTheFloor(t *testing.T) {
	node := &SamNode{
		BiscuitTimeout: 500 * time.Millisecond,
		nodeConfig:     &NodeConfigComplete{EgressRequireLabels: map[string]string{"jurisdiction": "eu"}},
	}
	cache, err := lru.New[string, time.Time](8)
	if err != nil {
		t.Fatal(err)
	}
	node.peerLabelGate = cache

	// No identity, so the biscuit fetch cannot succeed. Reaching that failure
	// is the proof the gate ran at all; returning nil would mean it skipped.
	err = node.VerifyPeerLabels(context.Background(), peer.ID("some-peer"), nil)
	if err == nil {
		t.Fatal("a caller requiring nothing must still be gated when a floor is configured")
	}

	// Without a floor, the same call is the documented no-op.
	node.nodeConfig = &NodeConfigComplete{}
	if err := node.VerifyPeerLabels(context.Background(), peer.ID("some-peer"), nil); err != nil {
		t.Errorf("with no floor and no requirement the gate must not run: %v", err)
	}
}

// The cache key has to separate the caller's requirement from the floor, or a
// pass recorded under one floor could be replayed under another.
func TestLabelGateKeySeparatesFloorFromRequirement(t *testing.T) {
	p := peer.ID("peer")
	a := labelGateKey(p, map[string]string{"jurisdiction": "eu"}, nil)
	b := labelGateKey(p, nil, map[string]string{"jurisdiction": "eu"})
	if a == b {
		t.Errorf("a requirement and a floor with the same pair must not share a cache key (%q)", a)
	}
}

// The key's separators are printable characters a label value is allowed to
// contain, so the encoding's unambiguity rests on ValidateLabelValue rejecting
// "=": a value can hold "|" or "#floor" but cannot forge the "|<key>=" that
// begins an entry. These are the shapes that would collide if it could.
func TestLabelGateKeyIsUnambiguousWithSeparatorsInValues(t *testing.T) {
	p := peer.ID("peer")
	// Every value here is valid input: the validator rejects only a comma, an
	// equals sign, and the three whitespace control characters.
	for _, v := range []string{"eu|x", "eu#floor", "#floor|b", "a|b#floor|c"} {
		if err := api.ValidateLabelValue(v); err != nil {
			t.Fatalf("test premise wrong, %q is not a valid label value: %v", v, err)
		}
	}

	seen := map[string][]string{}
	add := func(desc string, required, floor map[string]string) {
		k := labelGateKey(p, required, floor)
		seen[k] = append(seen[k], desc)
	}
	add("value carrying the entry separator", map[string]string{"a": "eu|x"}, nil)
	add("two entries", map[string]string{"a": "eu", "x": "1"}, nil)
	add("value carrying the floor marker", map[string]string{"a": "eu#floor"}, nil)
	add("floor holding the same pair", nil, map[string]string{"a": "eu"})
	add("requirement holding the same pair", map[string]string{"a": "eu"}, nil)
	add("value that looks like a floor section", map[string]string{"a": "#floor|b"}, nil)
	add("split across both sets", map[string]string{"a": "eu"}, map[string]string{"b": "1"})
	add("both sets, values with separators", map[string]string{"a": "a|b#floor|c"}, map[string]string{"b": "1"})

	for key, descs := range seen {
		if len(descs) > 1 {
			t.Errorf("these distinct inputs share cache key %q: %v", key, descs)
		}
	}
}
