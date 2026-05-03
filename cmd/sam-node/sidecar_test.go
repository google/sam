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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestWithAuth(t *testing.T) {
	token := "test-token"
	handler := withAuth(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "Valid token",
			authHeader:     "Bearer test-token",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Missing token",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid format",
			authHeader:     "test-token",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Wrong token",
			authHeader:     "Bearer wrong-token",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/any", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}

	t.Run("Empty token configured", func(t *testing.T) {
		handlerEmpty := withAuth("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest("GET", "/any", nil)
		req.Header.Set("Authorization", "Bearer anything")
		rr := httptest.NewRecorder()
		handlerEmpty.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})
}

func TestPublicEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/readyz", handleReadyz)

	endpoints := []string{"/healthz", "/readyz"}

	for _, ep := range endpoints {
		req := httptest.NewRequest("GET", ep, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status OK for %s, got %d", ep, rr.Code)
		}
	}
}

func TestHandleRegisterService(t *testing.T) {
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	d, err := dht.New(context.Background(), h, dht.Mode(dht.ModeServer), dht.ProtocolPrefix("/sam"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()

	// Create a second host to populate routing table
	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h2.Close() }()
	d2, err := dht.New(context.Background(), h2, dht.Mode(dht.ModeServer), dht.ProtocolPrefix("/sam"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d2.Close() }()

	err = h.Connect(context.Background(), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for DHT to recognize the peer
	time.Sleep(100 * time.Millisecond)

	node := &SamNode{
		services: make(map[string]bool),
		DHT:      d,
	}

	reqBody := ServiceRequest{ServiceName: "test-service"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/sam/service/register", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	handleRegisterService(node, rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d, body: %s", rr.Code, rr.Body.String())
	}

	if !node.IsServiceRegistered("test-service") {
		t.Errorf("expected service to be registered")
	}
}

func TestHandleUnregisterService(t *testing.T) {
	node := &SamNode{
		services: make(map[string]bool),
	}
	node.services["test-service"] = true

	reqBody := ServiceRequest{ServiceName: "test-service"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/sam/service/unregister", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	handleUnregisterService(node, rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", rr.Code)
	}

	if node.IsServiceRegistered("test-service") {
		t.Errorf("expected service to be unregistered")
	}
}
