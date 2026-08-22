package console

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/sam/api"
	"google.golang.org/protobuf/proto"
)

func TestNewServer_OIDCAutoDiscovery(t *testing.T) {
	// 1. Generate a mock RSA key for OIDC signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// 2. Start mock control plane + OIDC server
	var serverURL string
	mux := http.NewServeMux()

	// Mock Control Plane /info endpoint
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		resp := &api.ControlPlaneInfoResponse{
			OidcIssuer: serverURL,
			ClientId:   "mock-console-client",
		}
		data, err := proto.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	// Mock OIDC Discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := map[string]any{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/auth",
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/keys",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	})

	// Mock OIDC JWKS keys endpoint
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		// Minimum empty JWKS to satisfy client discovery
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"n":   privateKey.N.String(),
					"e":   "AQAB",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	mockSrv := httptest.NewServer(mux)
	defer mockSrv.Close()
	serverURL = mockSrv.URL

	// 3. Instantiate console Server with auto-discovery flags (empty issuer and client ID)
	cfg := Config{
		ControlPlaneURL: serverURL,
		AdminToken:      "test-admin-token",
		StaticDir:       t.TempDir(),
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// 4. Verify OIDC parameters were discovered and set
	if srv.provider == nil {
		t.Fatal("provider config was not initialized")
	}
	if srv.clientID != "mock-console-client" {
		t.Errorf("expected clientID 'mock-console-client', got '%s'", srv.clientID)
	}
	if srv.provider.Endpoint().AuthURL != serverURL+"/auth" {
		t.Errorf("expected AuthURL '%s', got '%s'", serverURL+"/auth", srv.provider.Endpoint().AuthURL)
	}
}

// TestNewServer_OIDCDiscoveryRetriesTransientFailure guards against a real
// deployment race: if the OIDC issuer (e.g. Dex) is still starting up when
// sam-console boots, discovery must retry instead of permanently disabling
// login for the life of the pod (console's /info reports healthy either way,
// so Kubernetes never restarts it to retry on its own).
func TestNewServer_OIDCDiscoveryRetriesTransientFailure(t *testing.T) {
	var attempts int32
	var serverURL string
	mux := http.NewServeMux()

	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		resp := &api.ControlPlaneInfoResponse{
			OidcIssuer: serverURL,
			ClientId:   "mock-console-client",
		}
		data, err := proto.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			http.Error(w, "upstream connect error", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/auth",
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/keys",
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{}})
	})

	mockSrv := httptest.NewServer(mux)
	defer mockSrv.Close()
	serverURL = mockSrv.URL

	srv, err := NewServer(Config{
		ControlPlaneURL: serverURL,
		AdminToken:      "test-admin-token",
		StaticDir:       t.TempDir(),
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if srv.provider == nil {
		t.Fatal("expected OIDC discovery to succeed after transient failures, provider is nil")
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("expected discovery to take 3 attempts, got %d", got)
	}
}

func TestDiscoverProviderWithRetry(t *testing.T) {
	t.Run("succeeds after transient failures", func(t *testing.T) {
		var attempts int32
		mux := http.NewServeMux()
		srv := httptest.NewServer(mux)
		defer srv.Close()
		issuer := srv.URL

		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&attempts, 1) < 3 {
				http.Error(w, "upstream connect error", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   issuer,
				"jwks_uri": issuer + "/keys",
			})
		})

		if _, err := discoverProviderWithRetry(context.Background(), issuer, 5, time.Millisecond, 5*time.Millisecond); err != nil {
			t.Fatalf("expected discovery to eventually succeed, got: %v", err)
		}
		if got := atomic.LoadInt32(&attempts); got != 3 {
			t.Errorf("expected 3 attempts, got %d", got)
		}
	})

	t.Run("gives up after max attempts", func(t *testing.T) {
		mux := http.NewServeMux()
		srv := httptest.NewServer(mux)
		defer srv.Close()

		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "always down", http.StatusServiceUnavailable)
		})

		if _, err := discoverProviderWithRetry(context.Background(), srv.URL, 3, time.Millisecond, 5*time.Millisecond); err == nil {
			t.Fatal("expected discovery to fail after exhausting retries")
		}
	})

	// A hung connection (issuer accepts but never responds) must not block
	// discovery forever: the client attached via oidc.ClientContext needs its
	// own timeout, since neither the retry loop nor context.Background() bound
	// a single attempt's duration on their own.
	t.Run("does not hang on an unresponsive issuer", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer func() { _ = ln.Close() }()
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn // accepted but deliberately never responds, to simulate a hang
			}
		}()

		client := &http.Client{Timeout: 50 * time.Millisecond}
		ctx := oidc.ClientContext(context.Background(), client)

		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = discoverProviderWithRetry(ctx, "http://"+ln.Addr().String(), 2, time.Millisecond, 5*time.Millisecond)
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("discoverProviderWithRetry hung on an unresponsive issuer instead of timing out")
		}
	})
}

// TestNewServer_BasePathServesBothPrefixes: with a BasePath the console must answer both the
// prefixed URLs it hands out (so a proxy can forward /console/* untouched) and the root.
func TestNewServer_BasePathServesBothPrefixes(t *testing.T) {
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // empty /info: no OIDC, which the console tolerates
	}))
	defer controlPlane.Close()

	srv, err := NewServer(Config{
		ControlPlaneURL: controlPlane.URL,
		AdminToken:      "test-admin-token",
		StaticDir:       t.TempDir(),
		BasePath:        "/console",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	console := httptest.NewServer(srv.Handler())
	defer console.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for path, want := range map[string]int{
		"/info":         http.StatusOK,
		"/console/info": http.StatusOK,
	} {
		resp, err := client.Get(console.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s: got %d, want %d", path, resp.StatusCode, want)
		}
	}

	// ServeMux sends the bare base path to the subtree root. Which 3xx it picks
	// is the standard library's business and has changed between Go releases;
	// what the console depends on is landing on /console/.
	resp, err := client.Get(console.URL + "/console")
	if err != nil {
		t.Fatalf("GET /console: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		t.Errorf("GET /console: got %d, want a redirect to the subtree root", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/console/" {
		t.Errorf("GET /console: Location = %q, want %q", got, "/console/")
	}
}

// BasePath is concatenated into cookie paths, redirect URLs and mux patterns, so malformed
// flag values (trailing slash, missing leading slash) must be normalized where the flag is read.
func TestNormalizeBasePath(t *testing.T) {
	for input, want := range map[string]string{
		"":               "",
		"/":              "",
		"/console":       "/console",
		"/console/":      "/console",
		"console":        "/console",
		"console//":      "/console",
		"//console":      "/console",
		"/console//sub/": "/console/sub",
	} {
		if got := NormalizeBasePath(input); got != want {
			t.Errorf("NormalizeBasePath(%q) = %q, want %q", input, got, want)
		}
	}
}
