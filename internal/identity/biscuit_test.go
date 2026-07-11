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

package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestMintBiscuitToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	policy := &api.PolicyConfig{
		Bindings: []api.Binding{
			{Role: "canary-role", Members: []string{"group:system:serviceaccounts:sam-canary"}},
			{Role: "canary-role", Members: []string{"user:system:serviceaccount:sam-canary:sam-node-sa"}},
		},
		Roles: map[string]api.RolePolicy{
			"admin": {
				AllowedServices: []string{"mcp:read", "mcp:write"},
				AllowedTargets:  []string{"mcp:target1"},
			},
			"canary-role": {
				AllowedServices: []string{"mcp:1.0.0"},
			},
		},
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	token := &oidc.IDToken{
		Expiry: time.Now().Add(1 * time.Hour),
	}

	// Case 1: Direct OIDC role (valid)
	claims1 := jwt.MapClaims{
		"roles": []any{"admin"},
	}
	biscuitData1, _, err := MintBiscuitToken(priv, claims1, token, dummyPeer, policy, token.Expiry)
	if err != nil {
		t.Fatal(err)
	}

	b1, err := biscuit.Unmarshal(biscuitData1)
	if err != nil {
		t.Fatal(err)
	}
	authorizer1, err := b1.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	rule1 := biscuit.Policy{Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
			Body: []biscuit.Predicate{
				{Name: "role", IDs: []biscuit.Term{biscuit.String("admin")}},
			},
		},
	}, Kind: biscuit.PolicyKindAllow}
	authorizer1.AddPolicy(rule1)
	authorizer1.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "allow_network_target",
		IDs:  []biscuit.Term{biscuit.String("mcp"), biscuit.String("target1")},
	}})
	if err := authorizer1.Authorize(); err != nil {
		t.Errorf("Expected direct role 'admin' to be authorized: %v", err)
	}

	// Case 2: OIDC group claim mapped to role via bindings
	claims2 := jwt.MapClaims{
		"groups": []any{"system:serviceaccounts:sam-canary"},
	}
	biscuitData2, _, err := MintBiscuitToken(priv, claims2, token, dummyPeer, policy, token.Expiry)
	if err != nil {
		t.Fatal(err)
	}

	b2, err := biscuit.Unmarshal(biscuitData2)
	if err != nil {
		t.Fatal(err)
	}
	authorizer2, err := b2.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	rule2 := biscuit.Policy{Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
			Body: []biscuit.Predicate{
				{Name: "role", IDs: []biscuit.Term{biscuit.String("canary-role")}},
			},
		},
	}, Kind: biscuit.PolicyKindAllow}
	authorizer2.AddPolicy(rule2)
	if err := authorizer2.Authorize(); err != nil {
		t.Errorf("Expected mapped role 'canary-role' to be authorized: %v", err)
	}

	// Case 3: Unmapped OIDC group and undefined direct role -> falls back to sam:role:node
	claims3 := jwt.MapClaims{
		"groups": []any{"unknown-group"},
		"roles":  []any{"undefined-role"},
	}
	biscuitData3, _, err := MintBiscuitToken(priv, claims3, token, dummyPeer, policy, token.Expiry)
	if err != nil {
		t.Fatal(err)
	}
	b3, err := biscuit.Unmarshal(biscuitData3)
	if err != nil {
		t.Fatal(err)
	}
	authorizer3, err := b3.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	rule3 := biscuit.Policy{Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
			Body: []biscuit.Predicate{
				{Name: "role", IDs: []biscuit.Term{biscuit.String(api.RoleNode)}},
			},
		},
	}, Kind: biscuit.PolicyKindAllow}
	authorizer3.AddPolicy(rule3)
	if err := authorizer3.Authorize(); err != nil {
		t.Errorf("Expected authorizer to pass fallback role '%s', got err: %v", api.RoleNode, err)
	}

	// Case 4: GKE Workload Identity projected token (no groups claim, sub-based mapping)
	claims4 := jwt.MapClaims{
		"sub": "system:serviceaccount:sam-canary:sam-node-sa",
	}
	biscuitData4, _, err := MintBiscuitToken(priv, claims4, token, dummyPeer, policy, token.Expiry)
	if err != nil {
		t.Fatal(err)
	}
	b4, err := biscuit.Unmarshal(biscuitData4)
	if err != nil {
		t.Fatal(err)
	}
	authorizer4, err := b4.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	rule4 := biscuit.Policy{Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
			Body: []biscuit.Predicate{
				{Name: "role", IDs: []biscuit.Term{biscuit.String("canary-role")}},
			},
		},
	}, Kind: biscuit.PolicyKindAllow}
	authorizer4.AddPolicy(rule4)
	if err := authorizer4.Authorize(); err != nil {
		t.Errorf("Expected sub-derived role 'canary-role' to be authorized: %v", err)
	}
}

func TestVerifyBiscuit_Expiration(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		expiry      time.Time
		expectError bool
	}{
		{
			name:        "Valid unexpired token",
			expiry:      time.Now().Add(1 * time.Hour),
			expectError: false,
		},
		{
			name:        "Expired token",
			expiry:      time.Now().Add(-1 * time.Hour),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &oidc.IDToken{
				Expiry: tt.expiry,
			}
			claims := jwt.MapClaims{
				"roles": []any{"admin"},
			}

			biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, &api.PolicyConfig{}, token.Expiry)
			if err != nil {
				t.Fatalf("MintBiscuitToken failed: %v", err)
			}

			_, err = VerifyBiscuit(biscuitData, dummyPeer, []ed25519.PublicKey{pub}, 500*time.Millisecond)
			if tt.expectError && err == nil {
				t.Errorf("Expected error due to expiration, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error, got: %v", err)
			}
		})
	}
}

func TestMintBiscuitToken_ClaimsTranslation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	policy := &api.PolicyConfig{
		Bindings: []api.Binding{
			{Role: "developer-role", Members: []string{"group:engineering"}},
		},
		Roles: map[string]api.RolePolicy{
			"developer-role": {
				AllowedServices: []string{"mcp:git-helper"},
			},
		},
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	token := &oidc.IDToken{
		Expiry: time.Now().Add(1 * time.Hour),
	}

	claims := jwt.MapClaims{
		"sub":    "user-12345",
		"email":  "agent@google.com",
		"groups": []any{"beta-testers", "engineering"},
	}

	biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, policy, token.Expiry)
	if err != nil {
		t.Fatalf("Failed to mint biscuit: %v", err)
	}

	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		t.Fatalf("Failed to unmarshal biscuit: %v", err)
	}

	authorizer, err := b.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
	if err != nil {
		t.Fatalf("Failed to get authorizer: %v", err)
	}

	// Verify user("user-12345") fact is present
	checkUser := biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: "user", IDs: []biscuit.Term{biscuit.String("user-12345")}},
			},
		},
	}}
	authorizer.AddCheck(checkUser)

	// Verify email("agent@google.com") fact is present
	checkEmail := biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: "email", IDs: []biscuit.Term{biscuit.String("agent@google.com")}},
			},
		},
	}}
	authorizer.AddCheck(checkEmail)

	// Verify group("beta-testers") fact is present
	checkGroupBeta := biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: "group", IDs: []biscuit.Term{biscuit.String("beta-testers")}},
			},
		},
	}}
	authorizer.AddCheck(checkGroupBeta)

	// Verify group("engineering") fact is present
	checkGroupEng := biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: "group", IDs: []biscuit.Term{biscuit.String("engineering")}},
			},
		},
	}}
	authorizer.AddCheck(checkGroupEng)

	authorizer.AddPolicy(biscuit.Policy{Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
			Body: []biscuit.Predicate{},
		},
	}, Kind: biscuit.PolicyKindAllow})

	if err := authorizer.Authorize(); err != nil {
		t.Errorf("Authorization/Checks failed: %v\nWorld:\n%s", err, authorizer.PrintWorld())
	}
}

func TestMintBiscuitToken_VariousClaimsTypes(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	policy := &api.PolicyConfig{
		Bindings: []api.Binding{
			{Role: "eng-role", Members: []string{"group:eng-group"}},
		},
		Roles: map[string]api.RolePolicy{
			"admin":    {},
			"eng-role": {},
		},
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	token := &oidc.IDToken{
		Expiry: time.Now().Add(1 * time.Hour),
	}

	tests := []struct {
		name           string
		rolesClaim     any
		groupsClaim    any
		expectedRoles  []string
		expectedGroups []string
	}{
		{
			name:           "String slice (standard go code paths)",
			rolesClaim:     []string{"admin"},
			groupsClaim:    []string{"eng-group", "beta"},
			expectedRoles:  []string{"admin", "eng-role"},
			expectedGroups: []string{"eng-group", "beta"},
		},
		{
			name:           "Interface slice (standard JSON unmarshalled jwt paths)",
			rolesClaim:     []any{"admin"},
			groupsClaim:    []any{"eng-group", "beta"},
			expectedRoles:  []string{"admin", "eng-role"},
			expectedGroups: []string{"eng-group", "beta"},
		},
		{
			name:           "Single string claims",
			rolesClaim:     "admin",
			groupsClaim:    "eng-group",
			expectedRoles:  []string{"admin", "eng-role"},
			expectedGroups: []string{"eng-group"},
		},
		{
			name:           "Missing or nil claims",
			rolesClaim:     nil,
			groupsClaim:    nil,
			expectedRoles:  nil,
			expectedGroups: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.MapClaims{}
			if tt.rolesClaim != nil {
				claims["roles"] = tt.rolesClaim
			}
			if tt.groupsClaim != nil {
				claims["groups"] = tt.groupsClaim
			}

			biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, policy, token.Expiry)
			if err != nil {
				t.Fatalf("MintBiscuitToken failed: %v", err)
			}

			b, err := biscuit.Unmarshal(biscuitData)
			if err != nil {
				t.Fatalf("Unmarshal biscuit failed: %v", err)
			}

			authorizer, err := b.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
			if err != nil {
				t.Fatalf("Authorizer failed: %v", err)
			}

			for _, r := range tt.expectedRoles {
				authorizer.AddCheck(biscuit.Check{Queries: []biscuit.Rule{
					{
						Body: []biscuit.Predicate{
							{Name: "role", IDs: []biscuit.Term{biscuit.String(r)}},
						},
					},
				}})
			}

			for _, g := range tt.expectedGroups {
				authorizer.AddCheck(biscuit.Check{Queries: []biscuit.Rule{
					{
						Body: []biscuit.Predicate{
							{Name: "group", IDs: []biscuit.Term{biscuit.String(g)}},
						},
					},
				}})
			}

			authorizer.AddPolicy(biscuit.Policy{Queries: []biscuit.Rule{
				{
					Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
					Body: []biscuit.Predicate{},
				},
			}, Kind: biscuit.PolicyKindAllow})

			if err := authorizer.Authorize(); err != nil {
				t.Errorf("Verification failed for case: %v\nWorld:\n%s", err, authorizer.PrintWorld())
			}
		})
	}
}

func TestVerifyBiscuit_Concurrent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	token := &oidc.IDToken{
		Expiry: time.Now().Add(1 * time.Hour),
	}
	claims := jwt.MapClaims{
		"sub":   "user-123",
		"roles": []any{"admin"},
	}

	biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, &api.PolicyConfig{}, token.Expiry)
	if err != nil {
		t.Fatalf("MintBiscuitToken failed: %v", err)
	}

	const workers = 50
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, err := VerifyBiscuit(biscuitData, dummyPeer, []ed25519.PublicKey{pub}, 500*time.Millisecond)
				if err != nil {
					t.Errorf("Concurrent verification failed: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestMintBiscuitToken_ErrorAggregation(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	policy := &api.PolicyConfig{
		Roles: map[string]api.RolePolicy{
			"admin": {
				CustomDatalog: []string{
					"invalid-datalog-fact(123", // syntax error
					"another-bad-fact);",       // syntax error
				},
			},
		},
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	token := &oidc.IDToken{
		Expiry: time.Now().Add(1 * time.Hour),
	}
	claims := jwt.MapClaims{
		"sub":   "user-123",
		"roles": []any{"admin"},
	}

	_, _, err = MintBiscuitToken(priv, claims, token, dummyPeer, policy, token.Expiry)
	if err == nil {
		t.Fatal("Expected MintBiscuitToken to fail on custom datalog syntax errors, got nil error")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "failed to parse custom fact") && !strings.Contains(errStr, "panic parsing custom fact") {
		t.Errorf("Expected error message to contain parse failure info, got: %s", errStr)
	}

	if !strings.Contains(errStr, "invalid-datalog-fact") || !strings.Contains(errStr, "another-bad-fact") {
		t.Errorf("Expected error to aggregate both failures, got: %s", errStr)
	}
}

func TestMintBiscuitToken_FactDeduplication(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	policy := &api.PolicyConfig{
		Bindings: []api.Binding{
			{Role: "role-a", Members: []string{"user:user-1"}},
			{Role: "role-b", Members: []string{"user:user-1"}},
		},
		Roles: map[string]api.RolePolicy{
			"role-a": {
				AllowedTargets: []string{"*:*"},
			},
			"role-b": {
				AllowedTargets: []string{"*:*"},
			},
		},
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	token := &oidc.IDToken{
		Expiry: time.Now().Add(1 * time.Hour),
	}
	claims := jwt.MapClaims{
		"sub": "user-1",
	}

	biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, policy, token.Expiry)
	if err != nil {
		t.Fatalf("MintBiscuitToken failed with duplicate facts: %v", err)
	}

	if len(biscuitData) == 0 {
		t.Error("Expected valid biscuit data, got empty")
	}
}

func TestMintBootstrapBiscuitToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	policy := &api.PolicyConfig{
		Roles: map[string]api.RolePolicy{
			"custom-node-role": {
				AllowedServices: []string{"mcp:service1"},
			},
		},
	}

	// Case 1: Router Role
	biscuitData1, err := MintBootstrapBiscuitToken(priv, dummyPeer, api.RoleRouter, time.Now().Add(1*time.Hour), policy)
	if err != nil {
		t.Fatal(err)
	}

	b1, err := biscuit.Unmarshal(biscuitData1)
	if err != nil {
		t.Fatal(err)
	}
	authorizer1, err := b1.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}

	// Verify right("relay") fact is present
	checkRelay := biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: api.FactRight, IDs: []biscuit.Term{biscuit.String(api.RightRelay)}},
			},
		},
	}}
	authorizer1.AddCheck(checkRelay)

	// Verify target_unrestricted() fact is present
	checkUnrestricted := biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: "target_unrestricted", IDs: []biscuit.Term{}},
			},
		},
	}}
	authorizer1.AddCheck(checkUnrestricted)

	authorizer1.AddPolicy(biscuit.Policy{Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
			Body: []biscuit.Predicate{},
		},
	}, Kind: biscuit.PolicyKindAllow})

	if err := authorizer1.Authorize(); err != nil {
		t.Errorf("Expected router facts checks to succeed: %v", err)
	}

	// Case 2: Custom Node Role
	biscuitData2, err := MintBootstrapBiscuitToken(priv, dummyPeer, "custom-node-role", time.Now().Add(1*time.Hour), policy)
	if err != nil {
		t.Fatal(err)
	}

	b2, err := biscuit.Unmarshal(biscuitData2)
	if err != nil {
		t.Fatal(err)
	}
	authorizer2, err := b2.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}

	// Verify exact match service fact derived from policy
	checkServiceExact := biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: "granted_service_exact", IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String("service1")}},
			},
		},
	}}
	authorizer2.AddCheck(checkServiceExact)

	authorizer2.AddPolicy(biscuit.Policy{Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
			Body: []biscuit.Predicate{},
		},
	}, Kind: biscuit.PolicyKindAllow})

	if err := authorizer2.Authorize(); err != nil {
		t.Errorf("Expected custom node role service checks to succeed: %v", err)
	}
}
