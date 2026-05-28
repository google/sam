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
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
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
			Roles: map[string]api.RolePolicy{
				"admin": {
					MCP: api.MCPPolicy{
						AllowedTools: []string{"read", "write"},
					},
					Network: api.NetworkPolicy{
						AllowedTargets: []string{"target1"},
					},
				},
			},
		},
	}

	claims := jwt.MapClaims{
		"roles": []any{"admin"},
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

	biscuitData, err := hub.mintBiscuitToken(claims, token, dummyPeer)
	if err != nil {
		t.Fatal(err)
	}

	if len(biscuitData) == 0 {
		t.Error("Expected non-empty biscuit data")
	}
}

func TestHandleInfoHTTP(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	kr, err := NewKeyRing(dbPath, 24*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kr.Close() }()

	oidcIssuer = "http://mock-issuer"

	hub := &Hub{
		KeyRing:          kr,
		AllowedAudiences: []string{"test-audience-1", "test-audience-2"},
	}

	handler := handleInfoHTTP(hub)

	req := httptest.NewRequest("GET", "/info", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var info api.HubInfoResponse
	if err := proto.Unmarshal(body, &info); err != nil {
		t.Fatalf("Failed to unmarshal protobuf: %v", err)
	}

	if info.OidcIssuer != "http://mock-issuer" {
		t.Errorf("Expected issuer 'http://mock-issuer', got %q", info.OidcIssuer)
	}

	if info.ClientId != "test-audience-1" {
		t.Errorf("Expected client ID 'test-audience-1', got %q", info.ClientId)
	}

	if info.Audience != "test-audience-1" {
		t.Errorf("Expected audience 'test-audience-1', got %q", info.Audience)
	}
}
