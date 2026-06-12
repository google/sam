package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestInteractiveLogin(t *testing.T) {
	origSSHClient := os.Getenv("SSH_CLIENT")
	origSSHTTY := os.Getenv("SSH_TTY")
	os.Unsetenv("SSH_CLIENT")
	os.Unsetenv("SSH_TTY")
	defer func() {
		os.Setenv("SSH_CLIENT", origSSHClient)
		os.Setenv("SSH_TTY", origSSHTTY)
	}()

	mux := http.NewServeMux()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "authorization_code" {
			http.Error(w, "Invalid grant_type", http.StatusBadRequest)
			return
		}
		if r.FormValue("code") != "dev_code_123" {
			http.Error(w, "Invalid code", http.StatusBadRequest)
			return
		}
		if r.FormValue("code_verifier") == "" {
			http.Error(w, "Missing code_verifier", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
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

	// Mock openBrowser to simulate the user authorizing in the browser
	originalOpenBrowser := openBrowserFunc
	openBrowserFunc = func(urlStr string) {
		u, _ := url.Parse(urlStr)
		redirectURI := u.Query().Get("redirect_uri")
		state := u.Query().Get("state")

		go func() {
			time.Sleep(100 * time.Millisecond)
			_, _ = http.Get(redirectURI + "?code=dev_code_123&state=" + state)
		}()
	}
	defer func() { openBrowserFunc = originalOpenBrowser }()

	token, err := node.InteractiveLogin(ctx, "http://auth.example.com/auth", server.URL+"/token", "client_id_test", "sam-e2e")
	if err != nil {
		t.Fatalf("InteractiveLogin failed: %v", err)
	}

	if token != "id_token_abc" {
		t.Errorf("Expected token 'id_token_abc', got '%s'", token)
	}
}

func TestDiscoverEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 "http://" + r.Host,
			"token_endpoint":         "http://" + r.Host + "/token",
			"authorization_endpoint": "http://" + r.Host + "/auth",
		}); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	node := &SamNode{}
	ctx := context.Background()

	tokenURL, authURL, err := node.DiscoverEndpoints(ctx, server.URL)
	if err != nil {
		t.Fatalf("DiscoverEndpoints failed: %v", err)
	}

	if tokenURL != server.URL+"/token" {
		t.Errorf("Expected tokenURL %s, got %s", server.URL+"/token", tokenURL)
	}
	if authURL != server.URL+"/auth" {
		t.Errorf("Expected authURL %s, got %s", server.URL+"/auth", authURL)
	}
}
