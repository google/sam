package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestInteractiveLogin(t *testing.T) {
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_TTY", "")

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

	node := &SamNode{BiscuitTimeout: 500 * time.Millisecond}

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

	token, err := node.InteractiveLogin(ctx, "http://auth.example.com/auth", server.URL+"/token", "client_id_test", "sam-e2e", false, false)
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

	node := &SamNode{BiscuitTimeout: 500 * time.Millisecond}
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

func TestInteractiveLoginWithRefresh(t *testing.T) {
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_TTY", "")

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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":  "access_token_xyz",
			"id_token":      "id_token_abc",
			"refresh_token": "refresh_token_123",
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Initialize Store
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	node := &SamNode{BiscuitTimeout: 500 * time.Millisecond, Store: store}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	originalOpenBrowser := openBrowserFunc
	openBrowserFunc = func(urlStr string) {
		u, _ := url.Parse(urlStr)
		redirectURI := u.Query().Get("redirect_uri")
		state := u.Query().Get("state")

		// Verify offline_access scope and prompt are present
		scope := u.Query().Get("scope")
		if !strings.Contains(scope, "offline_access") {
			t.Errorf("Expected scope to contain 'offline_access', got %q", scope)
		}
		if u.Query().Get("access_type") != "offline" {
			t.Errorf("Expected access_type to be 'offline', got %q", u.Query().Get("access_type"))
		}

		go func() {
			time.Sleep(100 * time.Millisecond)
			_, _ = http.Get(redirectURI + "?code=dev_code_123&state=" + state)
		}()
	}
	defer func() { openBrowserFunc = originalOpenBrowser }()

	token, err := node.InteractiveLogin(ctx, "http://auth.example.com/auth", server.URL+"/token", "client_id_test", "sam-e2e", true, false)
	if err != nil {
		t.Fatalf("InteractiveLogin failed: %v", err)
	}

	if token != "id_token_abc" {
		t.Errorf("Expected token 'id_token_abc', got '%s'", token)
	}

	// Verify refresh token is saved in the database
	savedRefresh, err := store.LoadRefreshToken()
	if err != nil {
		t.Fatalf("Failed to load refresh token from store: %v", err)
	}
	if savedRefresh != "refresh_token_123" {
		t.Errorf("Expected saved refresh token 'refresh_token_123', got '%s'", savedRefresh)
	}
}

func TestRenewWithRefreshToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 "http://" + r.Host,
			"token_endpoint":         "http://" + r.Host + "/token",
			"authorization_endpoint": "http://" + r.Host + "/auth",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "refresh_token" {
			http.Error(w, "Invalid grant_type: "+r.FormValue("grant_type"), http.StatusBadRequest)
			return
		}
		if r.FormValue("refresh_token") != "old_refresh_123" {
			http.Error(w, "Invalid refresh token", http.StatusBadRequest)
			return
		}
		if r.FormValue("client_id") != "client_id_test" {
			http.Error(w, "Invalid client_id", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":  "new_access_token_xyz",
			"id_token":      "new_id_token_abc",
			"refresh_token": "new_refresh_token_456",
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Initialize Store
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Store OIDC Config and old refresh token
	if err := store.SaveOIDCConfig(server.URL, "client_id_test", "sam-e2e"); err != nil {
		t.Fatalf("Failed to save OIDC Config: %v", err)
	}
	if err := store.SaveRefreshToken("old_refresh_123"); err != nil {
		t.Fatalf("Failed to save Refresh Token: %v", err)
	}

	node := &SamNode{BiscuitTimeout: 500 * time.Millisecond, Store: store}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	newJWT, err := node.renewWithRefreshToken(ctx, "")
	if err != nil {
		t.Fatalf("renewWithRefreshToken failed: %v", err)
	}

	if newJWT != "new_id_token_abc" {
		t.Errorf("Expected new JWT 'new_id_token_abc', got '%s'", newJWT)
	}

	// Verify that the new refresh token is saved
	newRefresh, err := store.LoadRefreshToken()
	if err != nil {
		t.Fatalf("Failed to load new refresh token from store: %v", err)
	}
	if newRefresh != "new_refresh_token_456" {
		t.Errorf("Expected updated refresh token 'new_refresh_token_456', got '%s'", newRefresh)
	}
}
