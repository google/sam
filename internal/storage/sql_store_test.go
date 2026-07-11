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

package storage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/sam/api"
)

func newTestStore(t *testing.T) Store {
	t.Helper()
	// Use a temporary file for SQLite testing to avoid concurrency sharing bugs in parallel tests
	tempDir, err := os.MkdirTemp("", "sam-store-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(tempDir)
	})

	dbPath := filepath.Join(tempDir, "test.db")
	store, err := NewSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	return store
}

func TestKeyRingOps(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Initial State: Keyring empty
	_, _, err := store.GetCurrentKey(ctx)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Generate and save initial key
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	err = store.SaveInitialKey(ctx, priv1, pub1)
	if err != nil {
		t.Fatalf("failed to save initial key: %v", err)
	}

	// GetCurrentKey
	curPriv, curPub, err := store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("failed to get current key: %v", err)
	}
	if !bytes.Equal(curPriv, priv1) || !bytes.Equal(curPub, pub1) {
		t.Fatalf("returned key pair does not match initial key pair")
	}

	// Get all valid keys (only 1 valid key right now)
	validKeys, err := store.GetAllValidKeys(ctx)
	if err != nil {
		t.Fatalf("failed to get all valid keys: %v", err)
	}
	if len(validKeys) != 1 {
		t.Fatalf("expected 1 valid key, got %d", len(validKeys))
	}
	if !bytes.Equal(validKeys[0].Private, priv1) {
		t.Fatalf("valid key mismatch")
	}

	// Rotate keys
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	gracePeriod := 1 * time.Hour
	err = store.RotateKeys(ctx, priv2, pub2, gracePeriod)
	if err != nil {
		t.Fatalf("failed to rotate keys: %v", err)
	}

	// GetCurrentKey should return the new key
	curPriv, curPub, err = store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("failed to get current key: %v", err)
	}
	if !bytes.Equal(curPriv, priv2) || !bytes.Equal(curPub, pub2) {
		t.Fatalf("returned key pair does not match rotated key pair")
	}

	// GetAllValidKeys should return both
	validKeys, err = store.GetAllValidKeys(ctx)
	if err != nil {
		t.Fatalf("failed to get all valid keys: %v", err)
	}
	if len(validKeys) != 2 {
		t.Fatalf("expected 2 valid keys, got %d", len(validKeys))
	}

	// Wait, check if key clean up works. Let's rotate with negative grace period to expire the second key immediately
	pub3, priv3, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	err = store.RotateKeys(ctx, priv3, pub3, -1*time.Second) // Expires immediately
	if err != nil {
		t.Fatalf("failed to rotate keys: %v", err)
	}

	// GetAllValidKeys should only return 2 keys now (the new current key [pub3] and key 2 [pub2] since it hasn't expired, but key 1 [pub1] was cleaned up because its expiration was reached)
	validKeys, err = store.GetAllValidKeys(ctx)
	if err != nil {
		t.Fatalf("failed to get all valid keys: %v", err)
	}
	if len(validKeys) != 2 {
		t.Fatalf("expected 2 valid keys, got %d", len(validKeys))
	}
}

func TestNodeEnrollmentOps(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	peerID := "12D3KooWLTpP4335eb4e414e21415eb66b"

	// Not enrolled yet
	_, err := store.GetNode(ctx, peerID)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	banned, err := store.IsNodeBanned(ctx, peerID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if banned {
		t.Fatalf("expected not banned by default")
	}

	// Enroll node
	biscuitData := []byte("some-biscuit-token")
	expiresAt := time.Now().Add(24 * time.Hour)
	err = store.EnrollNode(ctx, peerID, biscuitData, expiresAt)
	if err != nil {
		t.Fatalf("failed to enroll node: %v", err)
	}

	// Get node
	n, err := store.GetNode(ctx, peerID)
	if err != nil {
		t.Fatalf("failed to get enrolled node: %v", err)
	}
	if n.PeerID != peerID || !bytes.Equal(n.Biscuit, biscuitData) || n.Banned {
		t.Fatalf("node data mismatch: %+v", n)
	}

	// Ban node
	err = store.SetNodeBanned(ctx, peerID, true)
	if err != nil {
		t.Fatalf("failed to ban node: %v", err)
	}

	banned, err = store.IsNodeBanned(ctx, peerID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !banned {
		t.Fatalf("expected node to be banned")
	}

	// Re-enroll (unbans? No, re-enroll updates details, but let's check what our schema does. We set banned to false or keep? Wait, our EnrollNode query does 'FALSE' / 0 on INSERT, but during UPDATE it doesn't modify banned)
	err = store.EnrollNode(ctx, peerID, []byte("new-biscuit"), expiresAt)
	if err != nil {
		t.Fatalf("failed to enroll node: %v", err)
	}

	banned, err = store.IsNodeBanned(ctx, peerID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !banned {
		t.Fatalf("expected node to remain banned unless explicitly unbanned")
	}
}

func TestRouterLeaseOps(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	peerID := "12D3KooWLTpRouterPeer"

	// No routers
	routers, err := store.GetActiveRouters(ctx)
	if err != nil {
		t.Fatalf("failed to get active routers: %v", err)
	}
	if len(routers) != 0 {
		t.Fatalf("expected 0 routers, got %d", len(routers))
	}

	// Add a lease
	lease1 := &RouterLease{
		PeerID:      peerID,
		Addresses:   []string{"/ip4/127.0.0.1/tcp/5001/p2p/" + peerID},
		LastRenewal: time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Second),
	}
	err = store.UpsertRouterLease(ctx, lease1)
	if err != nil {
		t.Fatalf("failed to upsert router lease: %v", err)
	}

	// Get active routers
	routers, err = store.GetActiveRouters(ctx)
	if err != nil {
		t.Fatalf("failed to get active routers: %v", err)
	}
	if len(routers) != 1 {
		t.Fatalf("expected 1 router, got %d", len(routers))
	}
	if routers[0].PeerID != peerID || !reflect.DeepEqual(routers[0].Addresses, lease1.Addresses) {
		t.Fatalf("lease details mismatch: %+v", routers[0])
	}

	// Add an expired lease
	expiredLease := &RouterLease{
		PeerID:      "expired-router",
		Addresses:   []string{"/ip4/127.0.0.1/tcp/5002/p2p/expired-router"},
		LastRenewal: time.Now().Add(-5 * time.Minute),
		ExpiresAt:   time.Now().Add(-1 * time.Minute),
	}
	err = store.UpsertRouterLease(ctx, expiredLease)
	if err != nil {
		t.Fatalf("failed to upsert expired lease: %v", err)
	}

	// Active routers should still be 1
	routers, err = store.GetActiveRouters(ctx)
	if err != nil {
		t.Fatalf("failed to get active routers: %v", err)
	}
	if len(routers) != 1 {
		t.Fatalf("expected 1 router, got %d", len(routers))
	}
}

func TestPolicyOps(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Policy should be empty
	_, err := store.GetPolicy(ctx)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Save policy
	p := &api.PolicyConfig{
		Version: "v1alpha1",
		Bindings: []api.Binding{
			{Role: "admin", Members: []string{"user:alice"}},
		},
		Roles: map[string]api.RolePolicy{
			"admin": {
				AllowedServices: []string{"*"},
				AllowedTargets:  []string{"*"},
			},
		},
	}
	err = store.SavePolicy(ctx, p)
	if err != nil {
		t.Fatalf("failed to save policy: %v", err)
	}

	// Get policy
	retPolicy, err := store.GetPolicy(ctx)
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if retPolicy.Version != p.Version || len(retPolicy.Bindings) != 1 || retPolicy.Bindings[0].Role != "admin" {
		t.Fatalf("policy contents mismatch: %+v", retPolicy)
	}
}

func TestTimezoneComparison(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	peerID := "12D3KooWTimezoneRouter"

	// Create a lease with ExpiresAt using a different timezone (e.g., Eastern Standard Time)
	estZone := time.FixedZone("EST", -5*3600)
	expiresAt := time.Now().In(estZone).Add(10 * time.Second)

	lease := &RouterLease{
		PeerID:      peerID,
		Addresses:   []string{"/ip4/127.0.0.1/tcp/5001/p2p/" + peerID},
		LastRenewal: time.Now().In(estZone),
		ExpiresAt:   expiresAt,
	}

	if err := store.UpsertRouterLease(ctx, lease); err != nil {
		t.Fatalf("failed to upsert router lease: %v", err)
	}

	// Query using UTC timezone time
	routers, err := store.GetActiveRouters(ctx)
	if err != nil {
		t.Fatalf("failed to get active routers: %v", err)
	}

	if len(routers) != 1 {
		t.Fatalf("expected 1 router, got %d (timezone comparison failed)", len(routers))
	}
	if routers[0].PeerID != peerID {
		t.Fatalf("expected router %s, got %s", peerID, routers[0].PeerID)
	}
}

func TestBootstrapTokensAndEnrollmentRequestsOps(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// 1. Test BootstrapToken Operations
	tok := &BootstrapToken{
		ID:          "token-id-1",
		TokenHash:   "hash-1",
		Role:        "sam:role:router",
		MaxUsages:   5,
		UsagesCount: 0,
		Description: "Router join token",
		CreatedAt:   time.Now().Truncate(time.Second),
		ExpiresAt:   time.Now().Add(24 * time.Hour).Truncate(time.Second),
	}

	if err := store.SaveBootstrapToken(ctx, tok); err != nil {
		t.Fatalf("failed to save bootstrap token: %v", err)
	}

	ret, err := store.GetBootstrapToken(ctx, tok.ID)
	if err != nil {
		t.Fatalf("failed to get bootstrap token: %v", err)
	}
	if ret.TokenHash != tok.TokenHash || ret.Role != tok.Role || ret.MaxUsages != tok.MaxUsages {
		t.Errorf("retrieved token mismatch: %+v", ret)
	}

	if err := store.IncrementBootstrapTokenUsage(ctx, tok.ID); err != nil {
		t.Fatalf("failed to increment usage: %v", err)
	}
	ret2, _ := store.GetBootstrapToken(ctx, tok.ID)
	if ret2.UsagesCount != 1 {
		t.Errorf("expected usage count 1, got %d", ret2.UsagesCount)
	}

	// 2. Test EnrollmentRequest Operations
	req := &EnrollmentRequest{
		ID:           "req-id-1",
		PeerID:       "peer-id-1",
		PublicKey:    []byte("my-public-key-bytes"),
		TokenID:      tok.ID,
		Status:       api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING,
		BiscuitToken: nil,
		CreatedAt:    time.Now().Truncate(time.Second),
	}

	if err := store.CreateEnrollmentRequest(ctx, req); err != nil {
		t.Fatalf("failed to create enrollment request: %v", err)
	}

	gotReq, err := store.GetEnrollmentRequest(ctx, req.PeerID)
	if err != nil {
		t.Fatalf("failed to get enrollment request by PeerID: %v", err)
	}
	if gotReq.ID != req.ID || gotReq.Status != req.Status || !bytes.Equal(gotReq.PublicKey, req.PublicKey) {
		t.Errorf("retrieved request mismatch: %+v", gotReq)
	}

	gotReqByID, err := store.GetEnrollmentRequestByID(ctx, req.ID)
	if err != nil {
		t.Fatalf("failed to get enrollment request by ID: %v", err)
	}
	if gotReqByID.PeerID != req.PeerID {
		t.Errorf("retrieved request by ID mismatch: %+v", gotReqByID)
	}

	list, err := store.ListEnrollmentRequests(ctx)
	if err != nil {
		t.Fatalf("failed to list enrollment requests: %v", err)
	}
	if len(list) != 1 || list[0].ID != req.ID {
		t.Errorf("unexpected list size or content: %+v", list)
	}

	// 3. Test UpdateEnrollmentRequest
	biscuitToken := []byte("signed-biscuit-token-bytes")
	err = store.UpdateEnrollmentRequest(ctx, req.ID, api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED, biscuitToken, "admin-oidc")
	if err != nil {
		t.Fatalf("failed to update enrollment request: %v", err)
	}

	updatedReq, _ := store.GetEnrollmentRequestByID(ctx, req.ID)
	if updatedReq.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED || !bytes.Equal(updatedReq.BiscuitToken, biscuitToken) || updatedReq.ResolvedBy != "admin-oidc" || updatedReq.ResolvedAt == nil {
		t.Errorf("updated request details mismatch: %+v", updatedReq)
	}
}
