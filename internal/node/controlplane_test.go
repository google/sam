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
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
	"google.golang.org/protobuf/proto"
)

func TestMergeTrustedKeys(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-2 * time.Hour)
	keyA, _, _ := ed25519.GenerateKey(nil)
	keyB, _, _ := ed25519.GenerateKey(nil)
	keyC, _, _ := ed25519.GenerateKey(nil)

	existing := []TrustedKey{
		{Key: keyA, ReceivedAt: earlier},
		{Key: keyC, ReceivedAt: earlier}, // expired at the CP: absent from /keys
	}
	got := mergeTrustedKeys(existing, []ed25519.PublicKey{keyA, keyB}, now)

	if len(got) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(got))
	}
	if !got[0].Key.Equal(keyA) || !got[0].ReceivedAt.Equal(earlier) {
		t.Errorf("known key must keep its ReceivedAt: got %+v", got[0])
	}
	if !got[1].Key.Equal(keyB) || !got[1].ReceivedAt.Equal(now) {
		t.Errorf("new key must get the sync time: got %+v", got[1])
	}
	for _, tk := range got {
		if tk.Key.Equal(keyC) {
			t.Error("key expired at the control plane must be dropped")
		}
	}
}

func TestFetchControlPlaneInfo(t *testing.T) {
	expectedInfo := &api.ControlPlaneInfoResponse{
		RouterAddresses: []string{"/ip4/127.0.0.1/tcp/4001"},
		OidcIssuer:      "https://issuer.example.com",
		ClientId:        "client-id",
	}

	body, err := proto.Marshal(expectedInfo)
	if err != nil {
		t.Fatalf("Failed to marshal info: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/info" {
			t.Errorf("Expected path /info, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	info, err := FetchControlPlaneInfo(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("FetchControlPlaneInfo failed: %v", err)
	}

	if !reflect.DeepEqual(info.RouterAddresses, expectedInfo.RouterAddresses) {
		t.Errorf("Expected RouterAddresses %v, got %v", expectedInfo.RouterAddresses, info.RouterAddresses)
	}
	if info.OidcIssuer != expectedInfo.OidcIssuer {
		t.Errorf("Expected OidcIssuer %s, got %s", expectedInfo.OidcIssuer, info.OidcIssuer)
	}
	if info.ClientId != expectedInfo.ClientId {
		t.Errorf("Expected ClientId %s, got %s", expectedInfo.ClientId, info.ClientId)
	}
}

func TestFetchControlPlaneInfo_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := FetchControlPlaneInfo(context.Background(), server.URL)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), "control plane returned status 500 Internal Server Error") {
		t.Errorf("Expected error to contain '500 Internal Server Error', got %v", err)
	}
}

func TestFetchControlPlaneInfo_InvalidProto(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid data"))
	}))
	defer server.Close()

	_, err := FetchControlPlaneInfo(context.Background(), server.URL)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode /info response") {
		t.Errorf("Expected error to contain 'failed to decode /info response', got %v", err)
	}
}

func TestSyncMeshConfig(t *testing.T) {
	expectedInfo := &api.ControlPlaneInfoResponse{
		RouterAddresses: []string{"/ip4/127.0.0.1/tcp/4001"},
		OidcIssuer:      "https://issuer.example.com",
		ClientId:        "client-id",
	}

	body, err := proto.Marshal(expectedInfo)
	if err != nil {
		t.Fatalf("Failed to marshal info: %v", err)
	}

	cpPub, _, _ := ed25519.GenerateKey(nil)
	gracePub, _, _ := ed25519.GenerateKey(nil)
	keysBody, err := proto.Marshal(&api.KeysResponse{PublicKeys: [][]byte{cpPub, gracePub}})
	if err != nil {
		t.Fatalf("Failed to marshal keys: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/keys" {
			_, _ = w.Write(keysBody)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close() //nolint:errcheck

	// Initial store is empty, so SyncMeshConfig should just return empty
	pubKey, addrs, bannedPeerIDs, err := SyncMeshConfig(context.Background(), store)
	if err != nil {
		t.Fatalf("SyncMeshConfig failed: %v", err)
	}
	if len(bannedPeerIDs) != 0 {
		t.Errorf("Expected no banned peers for empty store, got %v", bannedPeerIDs)
	}
	if len(pubKey) != 0 || len(addrs) != 0 {
		t.Errorf("Expected empty result for empty store, got pubKey=%v, addrs=%v", pubKey, addrs)
	}

	// Save initial config with explicit control plane URL
	testPubKey := []byte("test-pub-key")
	if err := store.SaveMeshConfig(testPubKey, []string{"/ip4/1.2.3.4/tcp/1234"}); err != nil {
		t.Fatalf("Failed to save mesh config: %v", err)
	}
	if err := store.SaveControlPlaneURL(server.URL); err != nil {
		t.Fatalf("Failed to save control plane URL: %v", err)
	}

	// Call SyncMeshConfig, it should fetch new addrs from server
	pubKey, addrs, _, err = SyncMeshConfig(context.Background(), store)
	if err != nil {
		t.Fatalf("SyncMeshConfig failed: %v", err)
	}

	if string(pubKey) != string(testPubKey) {
		t.Errorf("Expected pubKey %s, got %s", testPubKey, pubKey)
	}

	if len(addrs) != 1 || addrs[0].String() != expectedInfo.RouterAddresses[0] {
		t.Errorf("Expected addrs %v, got %v", expectedInfo.RouterAddresses, addrs)
	}

	// Verify the new addrs were saved to the store
	savedPubKey, savedAddrsStr, err := store.LoadMeshConfig()
	if err != nil {
		t.Fatalf("Failed to load mesh config: %v", err)
	}
	if string(savedPubKey) != string(testPubKey) {
		t.Errorf("Expected saved pubKey %s, got %s", testPubKey, savedPubKey)
	}

	// The full valid key set from /keys must have been persisted
	trusted, err := store.LoadTrustedKeys()
	if err != nil {
		t.Fatalf("LoadTrustedKeys: %v", err)
	}
	if len(trusted) != 2 {
		t.Fatalf("expected 2 trusted keys from /keys, got %d", len(trusted))
	}
	if !trusted[0].Key.Equal(cpPub) || !trusted[1].Key.Equal(gracePub) {
		t.Errorf("persisted keys do not match /keys response")
	}
	if len(savedAddrsStr) != 1 || savedAddrsStr[0] != expectedInfo.RouterAddresses[0] {
		t.Errorf("Expected saved addrs %v, got %v", expectedInfo.RouterAddresses, savedAddrsStr)
	}
}
