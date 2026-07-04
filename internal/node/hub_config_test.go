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
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/google/sam/api"
	"google.golang.org/protobuf/proto"
)

func TestFetchHubInfo(t *testing.T) {
	expectedInfo := &api.HubInfoResponse{
		HubAddresses: []string{"/ip4/127.0.0.1/tcp/4001"},
		OidcIssuer:   "https://issuer.example.com",
		ClientId:     "client-id",
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

	info, err := FetchHubInfo(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("FetchHubInfo failed: %v", err)
	}

	if !reflect.DeepEqual(info.HubAddresses, expectedInfo.HubAddresses) {
		t.Errorf("Expected HubAddresses %v, got %v", expectedInfo.HubAddresses, info.HubAddresses)
	}
	if info.OidcIssuer != expectedInfo.OidcIssuer {
		t.Errorf("Expected OidcIssuer %s, got %s", expectedInfo.OidcIssuer, info.OidcIssuer)
	}
	if info.ClientId != expectedInfo.ClientId {
		t.Errorf("Expected ClientId %s, got %s", expectedInfo.ClientId, info.ClientId)
	}
}

func TestFetchHubInfo_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := FetchHubInfo(context.Background(), server.URL)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), "hub returned status 500 Internal Server Error") {
		t.Errorf("Expected error to contain '500 Internal Server Error', got %v", err)
	}
}

func TestFetchHubInfo_InvalidProto(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid data"))
	}))
	defer server.Close()

	_, err := FetchHubInfo(context.Background(), server.URL)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode /info response") {
		t.Errorf("Expected error to contain 'failed to decode /info response', got %v", err)
	}
}

func TestSyncHubConfig(t *testing.T) {
	expectedInfo := &api.HubInfoResponse{
		HubAddresses: []string{"/ip4/127.0.0.1/tcp/4001"},
		OidcIssuer:   "https://issuer.example.com",
		ClientId:     "client-id",
	}

	body, err := proto.Marshal(expectedInfo)
	if err != nil {
		t.Fatalf("Failed to marshal info: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close() //nolint:errcheck

	// Initial store is empty, so SyncHubConfig should just return empty
	pubKey, addrs, err := SyncHubConfig(context.Background(), store)
	if err != nil {
		t.Fatalf("SyncHubConfig failed: %v", err)
	}
	if len(pubKey) != 0 || len(addrs) != 0 {
		t.Errorf("Expected empty result for empty store, got pubKey=%v, addrs=%v", pubKey, addrs)
	}

	// Save initial config with explicit hub URL
	testPubKey := []byte("test-pub-key")
	if err := store.SaveHubConfig(testPubKey, []string{"/ip4/1.2.3.4/tcp/1234"}); err != nil {
		t.Fatalf("Failed to save hub config: %v", err)
	}
	if err := store.SaveHubURL(server.URL); err != nil {
		t.Fatalf("Failed to save hub url: %v", err)
	}

	// Call SyncHubConfig, it should fetch new addrs from server
	pubKey, addrs, err = SyncHubConfig(context.Background(), store)
	if err != nil {
		t.Fatalf("SyncHubConfig failed: %v", err)
	}

	if string(pubKey) != string(testPubKey) {
		t.Errorf("Expected pubKey %s, got %s", testPubKey, pubKey)
	}

	if len(addrs) != 1 || addrs[0].String() != expectedInfo.HubAddresses[0] {
		t.Errorf("Expected addrs %v, got %v", expectedInfo.HubAddresses, addrs)
	}

	// Verify the new addrs were saved to the store
	savedPubKey, savedAddrsStr, err := store.LoadHubConfig()
	if err != nil {
		t.Fatalf("Failed to load hub config: %v", err)
	}
	if string(savedPubKey) != string(testPubKey) {
		t.Errorf("Expected saved pubKey %s, got %s", testPubKey, savedPubKey)
	}
	if len(savedAddrsStr) != 1 || savedAddrsStr[0] != expectedInfo.HubAddresses[0] {
		t.Errorf("Expected saved addrs %v, got %v", expectedInfo.HubAddresses, savedAddrsStr)
	}
}
