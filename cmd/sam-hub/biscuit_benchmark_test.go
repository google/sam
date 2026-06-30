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
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func BenchmarkMintBiscuitToken(b *testing.B) {
	dir := b.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 24*time.Hour, nil)
	if err != nil {
		b.Fatal(err)
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
					AllowedServices: []string{"mcp:git-helper", "mcp:mcp-server-2"},
					AllowedTargets:  []string{"target-1", "target-2"},
					CustomDatalog: []string{
						"department(\"analytics\");",
					},
				},
			},
		},
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		b.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		b.Fatal(err)
	}

	token := &oidc.IDToken{
		Expiry: time.Now().Add(1 * time.Hour),
	}

	claims := jwt.MapClaims{
		"sub":    "user-12345",
		"email":  "agent@google.com",
		"groups": []any{"beta-testers", "engineering"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hub.mintBiscuitToken(claims, token, dummyPeer)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyBiscuit(b *testing.B) {
	dir := b.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 24*time.Hour, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = kr.Close() }()

	hub := &Hub{
		KeyRing:        kr,
		Policy:         &api.PolicyConfig{},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		b.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		b.Fatal(err)
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
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hub.verifyBiscuit(biscuitData, dummyPeer)
		if err != nil {
			b.Fatal(err)
		}
	}
}
