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
	"sync"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

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

			biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, token.Expiry, []string{"admin"})
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

	biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, token.Expiry, nil)
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

	biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, token.Expiry, []string{"admin"})
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

func TestMintBiscuitToken(t *testing.T) {
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
		"sub":    "test-user",
		"groups": []any{"group1", "group2"},
		"roles":  []any{"admin", "user"},
	}
	biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, token.Expiry, []string{"admin", "user"})
	if err != nil {
		t.Fatal(err)
	}

	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := b.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(500*time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}

	// Add policies to check that facts were added correctly.
	authorizer.AddPolicy(biscuit.Policy{Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
			Body: []biscuit.Predicate{
				{Name: "user", IDs: []biscuit.Term{biscuit.String("test-user")}},
				{Name: "group", IDs: []biscuit.Term{biscuit.String("group1")}},
				{Name: "group", IDs: []biscuit.Term{biscuit.String("group2")}},
				{Name: "role", IDs: []biscuit.Term{biscuit.String("admin")}},
				{Name: "role", IDs: []biscuit.Term{biscuit.String("user")}},
			},
		},
	}, Kind: biscuit.PolicyKindAllow})

	if err := authorizer.Authorize(); err != nil {
		t.Errorf("Expected facts to be present, got error: %v\nWorld:\n%s", err, authorizer.PrintWorld())
	}
}

func TestMintBiscuitToken_VariousClaimsTypes(t *testing.T) {
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

	tests := []struct {
		name           string
		rolesClaim     any
		groupsClaim    any
		expectedRoles  []string
		expectedGroups []string
	}{
		{
			name:           "String slice (standard go code paths)",
			rolesClaim:     []string{"admin", "eng-role"},
			groupsClaim:    []string{"eng-group", "beta"},
			expectedRoles:  []string{"admin", "eng-role"},
			expectedGroups: []string{"eng-group", "beta"},
		},
		{
			name:           "Interface slice (standard JSON unmarshalled jwt paths)",
			rolesClaim:     []any{"admin", "eng-role"},
			groupsClaim:    []any{"eng-group", "beta"},
			expectedRoles:  []string{"admin", "eng-role"},
			expectedGroups: []string{"eng-group", "beta"},
		},
		{
			name:           "Single string claims",
			rolesClaim:     "admin",
			groupsClaim:    "eng-group",
			expectedRoles:  []string{"admin"},
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

			biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, token.Expiry, tt.expectedRoles)
			if err != nil {
				t.Fatalf("MintBiscuitToken failed: %v", err)
			}

			b, err := biscuit.Unmarshal(biscuitData)
			if err != nil {
				t.Fatalf("Unmarshal biscuit failed: %v", err)
			}

			authorizer, err := b.Authorizer(pub)
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
				t.Errorf("Verification failed for case %s: %v\nWorld:\n%s", tt.name, err, authorizer.PrintWorld())
			}
		})
	}
}
