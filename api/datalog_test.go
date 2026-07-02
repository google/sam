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

package api

import (
	"crypto/ed25519"
	"crypto/rand"
	reflect "reflect"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
)

// helper to generate keypair for tests
func makeKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return pub, priv
}

func TestBaselinePolicies(t *testing.T) {
	pub, priv := makeKeyPair(t)

	tests := []struct {
		name          string
		tokenFacts    []biscuit.Fact
		requestTarget string // e.g. "mcp://calculator/add"
		expectAllow   bool
	}{
		{
			name: "Exact match allowed",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServiceExact, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String("calculator")}}},
			},
			requestTarget: "mcp://calculator",
			expectAllow:   true,
		},
		{
			name: "Exact match denied (mismatched service)",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServiceExact, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String("database")}}},
			},
			requestTarget: "mcp://calculator",
			expectAllow:   false,
		},
		{
			name: "Prefix wildcard allowed (subdomain prefix match)",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServicePrefix, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String("calc.")}}},
			},
			requestTarget: "mcp://calc.service.internal",
			expectAllow:   true,
		},
		{
			name: "Prefix wildcard denied (mismatched prefix)",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServicePrefix, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String("calc.")}}},
			},
			requestTarget: "mcp://db.service.internal",
			expectAllow:   false,
		},
		{
			name: "Suffix wildcard allowed (domain suffix match)",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServiceSuffix, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String(".internal")}}},
			},
			requestTarget: "mcp://calc.service.internal",
			expectAllow:   true,
		},
		{
			name: "Suffix wildcard denied (mismatched suffix)",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServiceSuffix, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String(".internal")}}},
			},
			requestTarget: "mcp://calc.service.external",
			expectAllow:   false,
		},
		{
			name: "All services matching scheme allowed",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServiceAll, IDs: []biscuit.Term{biscuit.String("mcp")}}},
			},
			requestTarget: "mcp://any-random-service",
			expectAllow:   true,
		},
		{
			name: "All services matching scheme denied (mismatched scheme)",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServiceAll, IDs: []biscuit.Term{biscuit.String("mcp")}}},
			},
			requestTarget: "inference://any-random-service",
			expectAllow:   false,
		},
		{
			name: "Global wildcard allows everything",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServiceAllTypes, IDs: []biscuit.Term{}}},
			},
			requestTarget: "mcp://calculator",
			expectAllow:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			for _, fact := range tt.tokenFacts {
				if err := builder.AddAuthorityFact(fact); err != nil {
					t.Fatalf("failed to add authority fact: %v", err)
				}
			}

			tok, err := builder.Build()
			if err != nil {
				t.Fatalf("failed to build token: %v", err)
			}

			authorizer, err := tok.Authorizer(pub)
			if err != nil {
				t.Fatalf("failed to create authorizer: %v", err)
			}

			// Parse target like middleware
			opType, opName := ParseServiceTarget(tt.requestTarget)
			authorizer.AddFact(biscuit.Fact{
				Predicate: biscuit.Predicate{
					Name: FactService,
					IDs:  []biscuit.Term{biscuit.String(opType), biscuit.String(opName)},
				},
			})

			// Add baseline policies
			for _, p := range BaselinePolicies {
				authorizer.AddPolicy(p)
			}

			err = authorizer.Authorize()
			if tt.expectAllow && err != nil {
				t.Errorf("expected authorized, got error: %v", err)
			} else if !tt.expectAllow && err == nil {
				t.Error("expected denied, but authorization succeeded")
			}
		})
	}
}

func TestBaselineReplayCheck(t *testing.T) {
	pub, priv := makeKeyPair(t)

	tests := []struct {
		name             string
		clientPeerID     string
		connectionPeerID string
		expectAllow      bool
	}{
		{
			name:             "Peer IDs match",
			clientPeerID:     "12D3KooWP2G8nJCLASp1Kb4TmQS4wCpMH2vpSUz8ug8DYEJiuf1i",
			connectionPeerID: "12D3KooWP2G8nJCLASp1Kb4TmQS4wCpMH2vpSUz8ug8DYEJiuf1i",
			expectAllow:      true,
		},
		{
			name:             "Peer IDs mismatch",
			clientPeerID:     "12D3KooWP2G8nJCLASp1Kb4TmQS4wCpMH2vpSUz8ug8DYEJiuf1i",
			connectionPeerID: "12D3KooWLgPBrLFKA533cKkXaecYUKfSZ48BkhwwYQ7ThDn1XwHb",
			expectAllow:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			// client_peer_id is embedded in the token authority block
			_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: FactClientPeerID,
				IDs:  []biscuit.Term{biscuit.String(tt.clientPeerID)},
			}})

			tok, _ := builder.Build()
			authorizer, _ := tok.Authorizer(pub)

			// connection_peer_id is injected as a runtime connection fact
			authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: FactConnectionPeerID,
				IDs:  []biscuit.Term{biscuit.String(tt.connectionPeerID)},
			}})

			// Add replay check and generic allow
			authorizer.AddCheck(BaselineReplayCheck)
			authorizer.AddPolicy(AllowIfTruePolicy)

			err := authorizer.Authorize()
			if tt.expectAllow && err != nil {
				t.Errorf("expected authorized, got error: %v", err)
			} else if !tt.expectAllow && err == nil {
				t.Error("expected denied, but authorization succeeded")
			}
		})
	}
}

func TestBaselineTargetCheck(t *testing.T) {
	pub, priv := makeKeyPair(t)

	tests := []struct {
		name        string
		tokenFacts  []biscuit.Fact
		targetFact  string // e.g. "node" or "group"
		targetVal   string // e.g. "12D3Koo..." or "backend"
		expectAllow bool
	}{
		{
			name: "Exact target matching allows",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactTargetRestricted}},
				{Predicate: biscuit.Predicate{Name: FactGrantedTargetExact, IDs: []biscuit.Term{biscuit.String("group"), biscuit.String("backend")}}},
			},
			targetFact:  "group",
			targetVal:   "backend",
			expectAllow: true,
		},
		{
			name: "Mismatched target denied when restricted",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactTargetRestricted}},
				{Predicate: biscuit.Predicate{Name: FactGrantedTargetExact, IDs: []biscuit.Term{biscuit.String("group"), biscuit.String("backend")}}},
			},
			targetFact:  "group",
			targetVal:   "frontend",
			expectAllow: false,
		},
		{
			name: "Any target allowed when target_unrestricted",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactTargetUnrestricted}},
			},
			targetFact:  "group",
			targetVal:   "any-group",
			expectAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			for _, fact := range tt.tokenFacts {
				_ = builder.AddAuthorityFact(fact)
			}

			tok, _ := builder.Build()
			authorizer, _ := tok.Authorizer(pub)

			// target_fact is evaluated at runtime (e.g. node(...) or group(...))
			authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: tt.targetFact,
				IDs:  []biscuit.Term{biscuit.String(tt.targetVal)},
			}})

			// Add target check, baseline rules, and generic allow
			authorizer.AddCheck(BaselineTargetCheck)
			for _, r := range BaselineRules {
				authorizer.AddRule(r)
			}
			// targetFactRules parses facts like node(...) -> target_fact("node", ...)
			for _, r := range TargetFactRules {
				authorizer.AddRule(r)
			}
			authorizer.AddPolicy(AllowIfTruePolicy)

			err := authorizer.Authorize()
			if tt.expectAllow && err != nil {
				t.Errorf("expected authorized, got error: %v", err)
			} else if !tt.expectAllow && err == nil {
				t.Error("expected denied, but authorization succeeded")
			}
		})
	}
}

func TestHubStaticTimeCheck(t *testing.T) {
	pub, priv := makeKeyPair(t)

	tests := []struct {
		name        string
		expiry      time.Time
		timeNow     time.Time
		expectAllow bool
	}{
		{
			name:        "Token not expired",
			expiry:      time.Now().Add(1 * time.Hour),
			timeNow:     time.Now(),
			expectAllow: true,
		},
		{
			name:        "Token expired",
			expiry:      time.Now().Add(-1 * time.Hour),
			timeNow:     time.Now(),
			expectAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: FactExpiration,
				IDs:  []biscuit.Term{biscuit.Date(tt.expiry)},
			}})

			tok, _ := builder.Build()
			authorizer, _ := tok.Authorizer(pub)

			authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: FactTime,
				IDs:  []biscuit.Term{biscuit.Date(tt.timeNow)},
			}})

			authorizer.AddCheck(HubStaticTimeCheck)
			authorizer.AddPolicy(AllowIfTruePolicy)

			err := authorizer.Authorize()
			if tt.expectAllow && err != nil {
				t.Errorf("expected authorized, got error: %v", err)
			} else if !tt.expectAllow && err == nil {
				t.Error("expected denied, but authorization succeeded")
			}
		})
	}
}

func TestOIDCClaimToFact(t *testing.T) {
	facts := OIDCClaimToFact()

	want := map[string]string{
		"sub":    FactUser,
		"email":  FactEmail,
		"groups": FactGroup,
	}

	if !reflect.DeepEqual(facts, want) {
		t.Errorf("OIDCClaimToFact() = %v, want %v", facts, want)
	}

	// Verify that modifying the returned map does not mutate the internal map.
	facts["new_claim"] = "new_fact"
	facts2 := OIDCClaimToFact()

	if _, ok := facts2["new_claim"]; ok {
		t.Errorf("OIDCClaimToFact() returned map is not a clone, modifications affect internal state")
	}
}
