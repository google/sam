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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/google/sam/api"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"
)

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

func TestFetchControlPlaneKeys(t *testing.T) {
	expectedKeys := &api.KeysResponse{
		PublicKeys: [][]byte{[]byte("key-one"), []byte("key-two")},
	}

	body, err := proto.Marshal(expectedKeys)
	if err != nil {
		t.Fatalf("Failed to marshal keys: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/keys" {
			t.Errorf("Expected path /keys, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	keys, err := FetchControlPlaneKeys(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("FetchControlPlaneKeys failed: %v", err)
	}

	if !reflect.DeepEqual(keys.PublicKeys, expectedKeys.PublicKeys) {
		t.Errorf("Expected PublicKeys %v, got %v", expectedKeys.PublicKeys, keys.PublicKeys)
	}
}

func TestHandleGetControlPlaneInfo(t *testing.T) {
	infoBody, err := proto.Marshal(&api.ControlPlaneInfoResponse{
		RouterAddresses: []string{"/dns4/router-a/tcp/4001/p2p/12D3KooRouterA"},
	})
	if err != nil {
		t.Fatalf("Failed to marshal info: %v", err)
	}
	keysBody, err := proto.Marshal(&api.KeysResponse{
		PublicKeys: [][]byte{[]byte("key-one")},
	})
	if err != nil {
		t.Fatalf("Failed to marshal keys: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(infoBody) })
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(keysBody) })
	server := httptest.NewServer(mux)
	defer server.Close()

	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	if err := store.SaveControlPlaneURL(server.URL); err != nil {
		t.Fatalf("Failed to save control plane URL: %v", err)
	}

	node := &SamNode{Store: store}
	result, _, err := node.handleGetControlPlaneInfo(context.Background(), nil, GetControlPlaneInfoParams{})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	text := result.Content[0].(*mcp.TextContent).Text
	var response struct {
		ControlPlaneURL string   `json:"control_plane_url"`
		RouterAddresses []string `json:"router_addresses"`
		SigningKeys     []string `json:"signing_keys"`
	}
	if err := json.Unmarshal([]byte(text), &response); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if response.ControlPlaneURL != server.URL {
		t.Errorf("Expected control_plane_url %s, got %s", server.URL, response.ControlPlaneURL)
	}
	if !reflect.DeepEqual(response.RouterAddresses, []string{"/dns4/router-a/tcp/4001/p2p/12D3KooRouterA"}) {
		t.Errorf("unexpected router_addresses: %v", response.RouterAddresses)
	}
	expectedKey := base64.StdEncoding.EncodeToString([]byte("key-one"))
	if !reflect.DeepEqual(response.SigningKeys, []string{expectedKey}) {
		t.Errorf("unexpected signing_keys: %v", response.SigningKeys)
	}
}

func TestHandleGetControlPlaneInfo_NoURL(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	node := &SamNode{Store: store}
	_, _, err = node.handleGetControlPlaneInfo(context.Background(), nil, GetControlPlaneInfoParams{})
	if err == nil {
		t.Fatal("Expected error for missing control plane URL, got nil")
	}
	if !strings.Contains(err.Error(), "no control plane URL stored") {
		t.Errorf("Expected 'no control plane URL stored' error, got %v", err)
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

	// Initial store is empty, so SyncMeshConfig should just return empty
	pubKey, addrs, err := SyncMeshConfig(context.Background(), store)
	if err != nil {
		t.Fatalf("SyncMeshConfig failed: %v", err)
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
	pubKey, addrs, err = SyncMeshConfig(context.Background(), store)
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
	if len(savedAddrsStr) != 1 || savedAddrsStr[0] != expectedInfo.RouterAddresses[0] {
		t.Errorf("Expected saved addrs %v, got %v", expectedInfo.RouterAddresses, savedAddrsStr)
	}
}
