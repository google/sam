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

package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/storage"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

func startCustomMockOIDC(t *testing.T) (string, func(claims map[string]interface{}) string) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	issuer := srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":   issuer,
			"jwks_uri": issuer + "/keys",
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": "mock-key",
					"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
				},
			},
		})
	})

	mintToken := func(customClaims map[string]interface{}) string {
		claims := jwt.MapClaims{
			"iss": issuer,
			"aud": "sam-mesh-audience",
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		for k, v := range customClaims {
			claims[k] = v
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "mock-key"
		jwtStr, err := token.SignedString(privKey)
		if err != nil {
			t.Fatalf("failed to sign jwt: %v", err)
		}
		return jwtStr
	}

	return issuer, mintToken
}

func setupTestServer(t *testing.T, oidcIssuer string) (*Server, storage.Store, string) {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "sam-cp-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(tempDir)
	})

	dbPath := filepath.Join(tempDir, "control-plane.db")
	store, err := storage.NewSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	opts := Options{
		ListenAddr:            "127.0.0.1:0", // Auto-allocate port
		DriverName:            "sqlite",
		DataSourceName:        dbPath,
		OIDCIssuer:            oidcIssuer,
		AllowedAudiences:      []string{"sam-mesh-audience"},
		LeaseDuration:         10 * time.Second,
		KeyRotationInterval:   12 * time.Hour,
		KeyGracePeriod:        10 * time.Minute,
		InsecureSkipTLSVerify: true,
		BiscuitTimeout:        1 * time.Second,
	}

	srv, err := NewServer(opts, store)
	if err != nil {
		t.Fatalf("failed to create control plane server: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start control plane server: %v", err)
	}

	serverAddr := srv.listener.Addr().String()

	return srv, store, "http://" + serverAddr
}

func TestControlPlaneBasic(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Test /info (no routers registered yet)
	resp, err := client.Get(baseURL + "/info")
	if err != nil {
		t.Fatalf("GET /info failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected GET /info status: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("failed to read /info body: %v", err)
	}

	var info api.HubInfoResponse
	if err := proto.Unmarshal(body, &info); err != nil {
		t.Fatalf("failed to unmarshal HubInfoResponse: %v", err)
	}
	if info.OidcIssuer != issuer || info.ClientId != "sam-mesh-audience" {
		t.Errorf("unexpected info response claims: %+v", &info)
	}
	if len(info.HubAddresses) != 0 {
		t.Errorf("expected 0 active routers, got %d", len(info.HubAddresses))
	}

	// 2. Test /keys
	resp, err = client.Get(baseURL + "/keys")
	if err != nil {
		t.Fatalf("GET /keys failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected GET /keys status: %s", resp.Status)
	}
	body, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("failed to read /keys body: %v", err)
	}

	var keys api.KeysResponse
	if err := proto.Unmarshal(body, &keys); err != nil {
		t.Fatalf("failed to unmarshal KeysResponse: %v", err)
	}
	if len(keys.PublicKeys) != 1 {
		t.Errorf("expected 1 valid public key, got %d", len(keys.PublicKeys))
	}
}

func TestNodeAndRouterRegistrationFlow(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	ctx := context.Background()

	// 1. Setup policy configuration in the database
	policy := &api.PolicyConfig{
		Version: "v1alpha1",
		Bindings: []api.Binding{
			{Role: "router", Members: []string{"group:routers"}},
			{Role: "user-role", Members: []string{"group:users"}},
		},
		Roles: map[string]api.RolePolicy{
			"router": {
				AllowedServices: []string{"*"},
				AllowedTargets:  []string{"*"},
			},
			"user-role": {
				AllowedServices: []string{"mcp:read"},
			},
		},
	}
	if err := store.SavePolicy(ctx, policy); err != nil {
		t.Fatalf("failed to seed policy: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// 2. Enroll a Node
	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	nodePeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	nodeJWT := mintToken(map[string]interface{}{
		"sub":    "node-alice",
		"groups": []string{"users"},
	})

	enrollNodeReq := &api.EnrollRequest{
		Jwt:    nodeJWT,
		PeerId: nodePeer.String(),
	}
	reqData, _ := proto.Marshal(enrollNodeReq)

	resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("node /register failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("node /register status failure: %s (body: %s)", resp.Status, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var enrollNodeResp api.EnrollResponse
	if err := proto.Unmarshal(body, &enrollNodeResp); err != nil {
		t.Fatalf("failed to unmarshal EnrollResponse: %v", err)
	}
	if len(enrollNodeResp.BiscuitToken) == 0 {
		t.Fatalf("received empty biscuit token for node")
	}

	// 3. Enroll a Router
	privRouter, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	routerPeer, err := peer.IDFromPrivateKey(privRouter)
	if err != nil {
		t.Fatal(err)
	}

	routerJWT := mintToken(map[string]interface{}{
		"sub":    "router-host-1",
		"groups": []string{"routers"},
	})

	enrollRouterReq := &api.EnrollRequest{
		Jwt:    routerJWT,
		PeerId: routerPeer.String(),
	}
	reqData, _ = proto.Marshal(enrollRouterReq)

	resp, err = client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("router /register failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("router /register status failure: %s", resp.Status)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var enrollRouterResp api.EnrollResponse
	if err := proto.Unmarshal(body, &enrollRouterResp); err != nil {
		t.Fatalf("failed to unmarshal EnrollResponse: %v", err)
	}
	if len(enrollRouterResp.BiscuitToken) == 0 {
		t.Fatalf("received empty biscuit token for router")
	}

	// 4. Register Router Lease
	routerAddresses := []string{"/ip4/127.0.0.1/tcp/5001/p2p/" + routerPeer.String()}
	leaseReq := &api.RouterLeaseRequest{
		PeerId:    routerPeer.String(),
		Addresses: routerAddresses,
		Biscuit:   enrollRouterResp.BiscuitToken,
	}
	reqData, _ = proto.Marshal(leaseReq)

	resp, err = client.Post(baseURL+"/routers/lease", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("POST /routers/lease failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /routers/lease status failure: %s (body: %s)", resp.Status, string(body))
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var leaseResp api.RouterLeaseResponse
	if err := proto.Unmarshal(body, &leaseResp); err != nil {
		t.Fatalf("failed to unmarshal RouterLeaseResponse: %v", err)
	}
	if !leaseResp.Success {
		t.Errorf("lease registration was not successful: %s", leaseResp.Error)
	}

	// 5. Query /info again, checking if the active router address list is now populated
	resp, err = client.Get(baseURL + "/info")
	if err != nil {
		t.Fatalf("GET /info failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var info api.HubInfoResponse
	_ = proto.Unmarshal(body, &info)

	if !reflect.DeepEqual(info.HubAddresses, routerAddresses) {
		t.Errorf("expected active routers address list %v, got %v", routerAddresses, info.HubAddresses)
	}

	// 6. Rogue Node tries to lease as a router (lacks 'router' role)
	rogueLeaseReq := &api.RouterLeaseRequest{
		PeerId:    nodePeer.String(),
		Addresses: []string{"/ip4/127.0.0.1/tcp/6001/p2p/" + nodePeer.String()},
		Biscuit:   enrollNodeResp.BiscuitToken, // Node biscuit doesn't have router role
	}
	reqData, _ = proto.Marshal(rogueLeaseReq)

	resp, err = client.Post(baseURL+"/routers/lease", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("POST rogue /routers/lease failed: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expectedStatusForbidden (403) for rogue router lease, got: %s", resp.Status)
	}
}

func TestPoliciesConfigurationREST(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Get policies (should return 404 since none exists)
	resp, err := client.Get(baseURL + "/policies")
	if err != nil {
		t.Fatalf("GET /policies failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for missing policy, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 2. Put policies
	newPolicyYaml := `
version: v1alpha1
bindings:
  - role: dev
    members:
      - group:developers
roles:
  dev:
    allowed_services:
      - mcp://git
`
	updateReq := &api.PolicyConfigUpdateRequest{YamlContent: newPolicyYaml}
	reqData, _ := proto.Marshal(updateReq)

	resp, err = client.Post(baseURL+"/policies", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("POST /policies failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected POST /policies status: %s (body: %s)", resp.Status, string(body))
	}
	_ = resp.Body.Close()

	// 3. Get policies again (verify content)
	resp, err = client.Get(baseURL + "/policies")
	if err != nil {
		t.Fatalf("GET /policies failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /policies status failed: %s", resp.Status)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var getResp api.PolicyConfigGetResponse
	if err := proto.Unmarshal(body, &getResp); err != nil {
		t.Fatalf("failed to unmarshal PolicyConfigGetResponse: %v", err)
	}

	if !strings.Contains(getResp.YamlContent, "role: dev") || !strings.Contains(getResp.YamlContent, "group:developers") {
		t.Errorf("returned policy content mismatch: %s", getResp.YamlContent)
	}
}
