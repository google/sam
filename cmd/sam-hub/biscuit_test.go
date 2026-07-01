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
	"path/filepath"
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
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 24*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kr.Close() }()

	hub := &Hub{
		KeyRing: kr,
		Policy: &api.PolicyConfig{
			Bindings: []api.Binding{
				{
					Group: "system:serviceaccounts:sam-canary",
					Role:  "canary-role",
				},
				{
					User: "system:serviceaccount:sam-canary:sam-node-sa",
					Role: "canary-role",
				},
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
		},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(priv)
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
	biscuitData1, err := hub.mintBiscuitToken(claims1, token, dummyPeer)
	if err != nil {
		t.Fatal(err)
	}
	if len(biscuitData1) == 0 {
		t.Error("Expected non-empty biscuit data for direct role")
	}

	b1, err := biscuit.Unmarshal(biscuitData1)
	if err != nil {
		t.Fatal(err)
	}
	authorizer1, err := b1.Authorizer(kr.GetCurrentPublicKey(), biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
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
	biscuitData2, err := hub.mintBiscuitToken(claims2, token, dummyPeer)
	if err != nil {
		t.Fatal(err)
	}
	if len(biscuitData2) == 0 {
		t.Error("Expected non-empty biscuit data for mapped group")
	}

	b2, err := biscuit.Unmarshal(biscuitData2)
	if err != nil {
		t.Fatal(err)
	}
	authorizer2, err := b2.Authorizer(kr.GetCurrentPublicKey(), biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
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

	// Case 3: Unmapped OIDC group and undefined direct role
	claims3 := jwt.MapClaims{
		"groups": []any{"unknown-group"},
		"roles":  []any{"undefined-role"},
	}
	biscuitData3, err := hub.mintBiscuitToken(claims3, token, dummyPeer)
	if err != nil {
		t.Fatal(err)
	}
	b3, err := biscuit.Unmarshal(biscuitData3)
	if err != nil {
		t.Fatal(err)
	}
	authorizer3, err := b3.Authorizer(kr.GetCurrentPublicKey(), biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	// Verify no role matches
	rule3 := biscuit.Policy{Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
			Body: []biscuit.Predicate{
				{Name: "role", IDs: []biscuit.Term{biscuit.Variable("any_role")}},
			},
		},
	}, Kind: biscuit.PolicyKindAllow}
	authorizer3.AddPolicy(rule3)
	if err := authorizer3.Authorize(); err == nil {
		t.Error("Expected authorizer to fail when checking for any roles in undefined configuration")
	}

	// Case 4: GKE Workload Identity projected token (no groups claim, sub-based mapping)
	claims4 := jwt.MapClaims{
		"sub": "system:serviceaccount:sam-canary:sam-node-sa",
	}
	biscuitData4, err := hub.mintBiscuitToken(claims4, token, dummyPeer)
	if err != nil {
		t.Fatal(err)
	}
	b4, err := biscuit.Unmarshal(biscuitData4)
	if err != nil {
		t.Fatal(err)
	}
	authorizer4, err := b4.Authorizer(kr.GetCurrentPublicKey(), biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	// Verify that it mapped the derived group "system:serviceaccounts:sam-canary" to "canary-role"
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
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 24*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kr.Close() }()

	hub := &Hub{
		KeyRing:        kr,
		Policy:         &api.PolicyConfig{},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(priv)
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

			biscuitData, err := hub.mintBiscuitToken(claims, token, dummyPeer)
			if err != nil {
				t.Fatalf("mintBiscuitToken failed: %v", err)
			}

			_, err = hub.verifyBiscuit(biscuitData, dummyPeer)
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
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 24*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kr.Close() }()

	hub := &Hub{
		KeyRing: kr,
		Policy: &api.PolicyConfig{
			Bindings: []api.Binding{
				{
					Group: "engineering",
					Role:  "developer-role",
				},
			},
			Roles: map[string]api.RolePolicy{
				"developer-role": {
					AllowedServices: []string{"mcp:git-helper"},
				},
			},
		},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(priv)
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

	biscuitData, err := hub.mintBiscuitToken(claims, token, dummyPeer)
	if err != nil {
		t.Fatalf("Failed to mint biscuit: %v", err)
	}

	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		t.Fatalf("Failed to unmarshal biscuit: %v", err)
	}

	authorizer, err := b.Authorizer(kr.GetCurrentPublicKey(), biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
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

	// To authorize, we also need to allow since checks run in authorizer.
	// We will add an allow policy that matches anything
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

func TestMintBiscuitToken_NilToken(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 24*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kr.Close() }()

	hub := &Hub{
		KeyRing:        kr,
		BiscuitTimeout: 500 * time.Millisecond,
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	claims := jwt.MapClaims{"sub": "user-123"}
	_, err = hub.mintBiscuitToken(claims, nil, dummyPeer)
	if err == nil {
		t.Error("Expected mintBiscuitToken to fail with nil token, got nil error")
	}
}

func TestMintBiscuitToken_NilClaims(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 24*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kr.Close() }()

	hub := &Hub{
		KeyRing:        kr,
		BiscuitTimeout: 500 * time.Millisecond,
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	token := &oidc.IDToken{
		Expiry: time.Now().Add(1 * time.Hour),
	}

	_, err = hub.mintBiscuitToken(nil, token, dummyPeer)
	if err == nil {
		t.Error("Expected mintBiscuitToken to fail with nil claims, got nil error")
	}
}

func TestMintBiscuitToken_VariousClaimsTypes(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 24*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kr.Close() }()

	hub := &Hub{
		KeyRing: kr,
		Policy: &api.PolicyConfig{
			Bindings: []api.Binding{
				{
					Group: "eng-group",
					Role:  "eng-role",
				},
			},
			Roles: map[string]api.RolePolicy{
				"admin":    {},
				"eng-role": {},
			},
		},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(priv)
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
			expectedRoles:  []string{"admin", "eng-role"}, // eng-role comes from eng-group mapping
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

			biscuitData, err := hub.mintBiscuitToken(claims, token, dummyPeer)
			if err != nil {
				t.Fatalf("mintBiscuitToken failed: %v", err)
			}

			b, err := biscuit.Unmarshal(biscuitData)
			if err != nil {
				t.Fatalf("Unmarshal biscuit failed: %v", err)
			}

			authorizer, err := b.Authorizer(kr.GetCurrentPublicKey(), biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
			if err != nil {
				t.Fatalf("Authorizer failed: %v", err)
			}

			// Add checks to verify the output facts
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
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 24*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kr.Close() }()

	hub := &Hub{
		KeyRing:        kr,
		Policy:         &api.PolicyConfig{},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(priv)
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

	biscuitData, err := hub.mintBiscuitToken(claims, token, dummyPeer)
	if err != nil {
		t.Fatalf("mintBiscuitToken failed: %v", err)
	}

	// Spin up 50 goroutines performing verification concurrently to detect any data races on static check/policy globals
	const workers = 50
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, err := hub.verifyBiscuit(biscuitData, dummyPeer)
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
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 24*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kr.Close() }()

	hub := &Hub{
		KeyRing: kr,
		Policy: &api.PolicyConfig{
			Roles: map[string]api.RolePolicy{
				"admin": {
					CustomDatalog: []string{
						"invalid-datalog-fact(123", // syntax error
						"another-bad-fact);",       // syntax error
					},
				},
			},
		},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(priv)
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

	_, err = hub.mintBiscuitToken(claims, token, dummyPeer)
	if err == nil {
		t.Fatal("Expected mintBiscuitToken to fail on custom datalog syntax errors, got nil error")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "failed to parse custom fact") && !strings.Contains(errStr, "panic parsing custom fact") {
		t.Errorf("Expected error message to contain parse failure info, got: %s", errStr)
	}

	// Verify that BOTH errors are aggregated in the error message
	if !strings.Contains(errStr, "invalid-datalog-fact") || !strings.Contains(errStr, "another-bad-fact") {
		t.Errorf("Expected error to aggregate both failures, got: %s", errStr)
	}
}
