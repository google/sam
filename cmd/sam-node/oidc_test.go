package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestInteractiveLogin(t *testing.T) {
	// Mock OIDC server
	mux := http.NewServeMux()

	// State for polling
	var authorized atomic.Bool

	mux.HandleFunc("/device/code", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":      "dev_code_123",
			"user_code":        "ABCD-1234",
			"verification_uri": "http://example.com/verify",
			"expires_in":       60,
			"interval":         1, // Fast polling for test
		}); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		if !authorized.Load() {
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{
				"error": "authorization_pending",
			}); err != nil {
				t.Errorf("Failed to encode response: %v", err)
			}
			return
		}

		if err := json.NewEncoder(w).Encode(map[string]string{
			"access_token": "access_token_xyz",
			"id_token":     "id_token_abc",
		}); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	node := &SamNode{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Run InteractiveLogin in a goroutine because it blocks
	type result struct {
		token string
		err   error
	}
	resChan := make(chan result, 1)

	go func() {
		token, err := node.InteractiveLogin(ctx, server.URL+"/device/code", server.URL+"/token", "client_id_test", "sam-e2e")
		resChan <- result{token, err}
	}()

	// Wait a bit and then authorize the user
	time.Sleep(1500 * time.Millisecond)
	authorized.Store(true)

	res := <-resChan
	if res.err != nil {
		t.Fatalf("InteractiveLogin failed: %v", res.err)
	}

	if res.token != "id_token_abc" {
		t.Errorf("Expected token 'id_token_abc', got '%s'", res.token)
	}
}

func TestDiscoverEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                        "http://" + r.Host,
			"token_endpoint":                "http://" + r.Host + "/token",
			"device_authorization_endpoint": "http://" + r.Host + "/device/code",
		}); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	node := &SamNode{}
	ctx := context.Background()

	tokenURL, deviceURL, err := node.DiscoverEndpoints(ctx, server.URL)
	if err != nil {
		t.Fatalf("DiscoverEndpoints failed: %v", err)
	}

	if tokenURL != server.URL+"/token" {
		t.Errorf("Expected tokenURL %s, got %s", server.URL+"/token", tokenURL)
	}
	if deviceURL != server.URL+"/device/code" {
		t.Errorf("Expected deviceURL %s, got %s", server.URL+"/device/code", deviceURL)
	}
}
