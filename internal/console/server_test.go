package console

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/sam/api"
	"google.golang.org/protobuf/proto"
)

func TestNewServer_OIDCAutoDiscovery(t *testing.T) {
	// 1. Generate a mock RSA key for OIDC signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// 2. Start mock Hub + OIDC server
	var serverURL string
	mux := http.NewServeMux()

	// Mock Control Plane /info endpoint
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		resp := &api.HubInfoResponse{
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
		HubURL:     serverURL,
		AdminToken: "test-admin-token",
		StaticDir:  t.TempDir(),
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
