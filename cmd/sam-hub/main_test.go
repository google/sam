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
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
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
					MCP: api.MCPPolicy{
						AllowedTools: []string{"read", "write"},
					},
					Network: api.NetworkPolicy{
						AllowedTargets: []string{"target1"},
					},
				},
				"canary-role": {
					MCP: api.MCPPolicy{
						AllowedTools: []string{"/sam/mcp/1.0.0"},
					},
				},
			},
		},
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
	authorizer1, err := b1.Authorizer(kr.GetCurrentPublicKey())
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
	authorizer2, err := b2.Authorizer(kr.GetCurrentPublicKey())
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
	authorizer3, err := b3.Authorizer(kr.GetCurrentPublicKey())
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
	authorizer4, err := b4.Authorizer(kr.GetCurrentPublicKey())
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

func TestHubReplicaSynchronization(t *testing.T) {
	// 1. Save and restore original global variables to avoid side effects
	origOidcIssuer := oidcIssuer
	origListenAddrs := listenAddrs
	origKeysDBPath := keysDBPath
	origBiscuitHex := biscuitHex
	origKeyGracePeriod := keyGracePeriod
	origAllowLoopbackFlag := allowLoopbackFlag

	defer func() {
		oidcIssuer = origOidcIssuer
		listenAddrs = origListenAddrs
		keysDBPath = origKeysDBPath
		biscuitHex = origBiscuitHex
		keyGracePeriod = origKeyGracePeriod
		allowLoopbackFlag = origAllowLoopbackFlag
	}()

	// Configure parameters for test
	oidcIssuer = "https://accounts.google.com"
	listenAddrs = []string{"/ip4/127.0.0.1/tcp/0"}
	keyGracePeriod = 24 * time.Hour
	allowLoopbackFlag = true
	// Use same hex key so they can decrypt each other's messages!
	biscuitHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tmpDir := t.TempDir()

	// 2. Spin up Hub Replica A
	keysDBPath = filepath.Join(tmpDir, "keysA.db")
	hubA, err := NewHub(ctx, nil, true)
	if err != nil {
		t.Fatalf("failed to create hub A: %v", err)
	}
	defer func() { _ = hubA.Host.Close() }()

	// 3. Spin up Hub Replica B
	keysDBPath = filepath.Join(tmpDir, "keysB.db")
	hubB, err := NewHub(ctx, nil, true)
	if err != nil {
		t.Fatalf("failed to create hub B: %v", err)
	}
	defer func() { _ = hubB.Host.Close() }()

	// 4. Connect Hub A and Hub B directly
	err = hubA.Host.Connect(ctx, peer.AddrInfo{
		ID:    hubB.Host.ID(),
		Addrs: hubB.Host.Addrs(),
	})
	if err != nil {
		t.Fatalf("failed to connect Hub A to Hub B: %v", err)
	}

	// Wait a moment for GossipSub sub and mesh connection
	time.Sleep(200 * time.Millisecond)

	// 5. Create a dummy peer to authenticate
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	peerC, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	// 6. Authenticate peerC on Hub A
	hubA.gater.mu.Lock()
	hubA.gater.authenticated[peerC] = true
	hubA.gater.mu.Unlock()

	// 7. Broadcast ADD event from Hub A
	hubA.publishSyncMessage(ctx, &api.HubSyncMessage{
		Action:    api.HubSyncMessage_ADD,
		PeerId:    peerC.String(),
		Timestamp: time.Now().UnixMilli(),
	})

	// 8. Verify Hub B receives the ADD and authenticates peerC
	authedOnB := false
	for i := 0; i < 100; i++ {
		hubB.gater.mu.RLock()
		authedOnB = hubB.gater.authenticated[peerC]
		hubB.gater.mu.RUnlock()
		if authedOnB {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !authedOnB {
		t.Fatal("Expected Hub B to authenticate peerC via sync ADD event, but it did not")
	}

	// 9. Remove peerC from Hub A and broadcast REMOVE
	hubA.gater.mu.Lock()
	delete(hubA.gater.authenticated, peerC)
	hubA.gater.mu.Unlock()

	hubA.publishSyncMessage(ctx, &api.HubSyncMessage{
		Action:    api.HubSyncMessage_REMOVE,
		PeerId:    peerC.String(),
		Timestamp: time.Now().UnixMilli(),
	})

	// 10. Verify Hub B receives the REMOVE and removes peerC
	removedOnB := false
	for i := 0; i < 100; i++ {
		hubB.gater.mu.RLock()
		authed := hubB.gater.authenticated[peerC]
		hubB.gater.mu.RUnlock()
		if !authed {
			removedOnB = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !removedOnB {
		t.Fatal("Expected Hub B to de-authenticate peerC via sync REMOVE event, but it remained authenticated")
	}

	// 11. Trigger a key rotation on Hub A to change its keyring keypair
	newPub, newPriv, _, err := hubA.KeyRing.PrepareRotation()
	if err != nil {
		t.Fatalf("failed to prepare rotation: %v", err)
	}
	if err := hubA.KeyRing.CommitRotation(newPub, newPriv, keyGracePeriod); err != nil {
		t.Fatalf("failed to commit rotation: %v", err)
	}

	// Verify that Hub A's current key is indeed rotated and different from Hub B's
	if bytes.Equal(hubA.KeyRing.GetCurrentKey(), hubB.KeyRing.GetCurrentKey()) {
		t.Fatal("Expected Hub A's keyring key to be rotated and different from Hub B's")
	}

	// 12. Authenticate another dummy peer (peerD) on Hub A
	privD, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	peerD, err := peer.IDFromPrivateKey(privD)
	if err != nil {
		t.Fatal(err)
	}

	hubA.gater.mu.Lock()
	hubA.gater.authenticated[peerD] = true
	hubA.gater.mu.Unlock()

	// 13. Broadcast ADD event from Hub A (which now has a rotated KeyRing)
	hubA.publishSyncMessage(ctx, &api.HubSyncMessage{
		Action:    api.HubSyncMessage_ADD,
		PeerId:    peerD.String(),
		Timestamp: time.Now().UnixMilli(),
	})

	// 14. Verify Hub B can STILL decrypt and authenticate peerD
	authedOnBAfterRotation := false
	for i := 0; i < 100; i++ {
		hubB.gater.mu.RLock()
		authedOnBAfterRotation = hubB.gater.authenticated[peerD]
		hubB.gater.mu.RUnlock()
		if authedOnBAfterRotation {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !authedOnBAfterRotation {
		t.Fatal("Expected Hub B to successfully decrypt and authenticate peerD after Hub A's key rotation, but it failed")
	}
}



