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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/announce"
	"github.com/google/sam/internal/catalog"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
)

func newTestIdentity(t *testing.T) (crypto.PrivKey, peer.ID) {
	t.Helper()
	priv, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("IDFromPublicKey: %v", err)
	}
	return priv, pid
}

func buildSSEEvent(t *testing.T, serviceType api.ServiceType, name string) string {
	t.Helper()
	priv, pid := newTestIdentity(t)
	info := &api.ServiceInfo{Type: serviceType, Name: name}
	a := announce.Build(info, pid, nil, time.Now(), announce.TTL)
	if err := announce.Sign(priv, a); err != nil {
		t.Fatalf("sign: %v", err)
	}
	data, err := protojson.Marshal(a)
	if err != nil {
		t.Fatalf("protojson marshal: %v", err)
	}
	return fmt.Sprintf("data: %s\n\n", data)
}

// TestTailPopulatesStoreFromSSE verifies that tail ingests two SSE announce events into the store.
func TestTailPopulatesStoreFromSSE(t *testing.T) {
	ev1 := buildSSEEvent(t, api.ServiceType_SERVICE_TYPE_MCP, "tool-a")
	ev2 := buildSSEEvent(t, api.ServiceType_SERVICE_TYPE_INFERENCE, "model-b")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = fmt.Fprint(w, ev1)
		_, _ = fmt.Fprint(w, ev2)
		if flusher != nil {
			flusher.Flush()
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	store := catalog.New()
	client := newNodeClient(srv.URL, "test-token")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() { _ = client.tail(ctx, store) }()

	// Wait up to 2s for 2 entries to land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(store.List(api.ServiceType_SERVICE_TYPE_UNSPECIFIED, "")) == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()

	entries := store.List(api.ServiceType_SERVICE_TYPE_UNSPECIFIED, "")
	if got := len(entries); got != 2 {
		t.Fatalf("expected 2 entries in store, got %d", got)
	}
}

// TestBootstrapUpsertsSyntheticAnnounces verifies bootstrap queries per type and upserts entries.
func TestBootstrapUpsertsSyntheticAnnounces(t *testing.T) {
	_, pid1 := newTestIdentity(t)
	_, pid2 := newTestIdentity(t)

	providers := map[string][]*api.DiscoveredProvider{
		"mcp": {
			{PeerId: pid1.String(), SrvName: "tool-x"},
		},
		"inference": {
			{PeerId: pid2.String(), SrvName: "model-y"},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		typeParam := r.URL.Query().Get("type")
		list, ok := providers[typeParam]
		if !ok {
			http.Error(w, "unknown type", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Mirror the node: json.NewEncoder uses struct json tags (snake_case).
		_ = json.NewEncoder(w).Encode(list)
	}))
	defer srv.Close()

	store := catalog.New()
	client := newNodeClient(srv.URL, "test-token")

	ctx := context.Background()
	if err := client.bootstrap(ctx, store, []api.ServiceType{
		api.ServiceType_SERVICE_TYPE_MCP,
		api.ServiceType_SERVICE_TYPE_INFERENCE,
	}); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	entries := store.List(api.ServiceType_SERVICE_TYPE_UNSPECIFIED, "")
	if got := len(entries); got != 2 {
		t.Fatalf("expected 2 entries after bootstrap, got %d", got)
	}
}
