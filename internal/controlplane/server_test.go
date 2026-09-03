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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/node"
	"github.com/google/sam/internal/storage"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
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

func setupTestServer(t *testing.T, oidcIssuer string, overrides ...func(*Options)) (*Server, storage.Store, string) {
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
		BiscuitTimeout:        10 * time.Second,
	}
	for _, fn := range overrides {
		fn(&opts)
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

	// Test /healthz
	respHealth, err := client.Get(baseURL + "/healthz")
	if err != nil || respHealth.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz failed: %v, status: %v", err, respHealth.Status)
	}
	_ = respHealth.Body.Close()

	// Test /readyz
	respReady, err := client.Get(baseURL + "/readyz")
	if err != nil || respReady.StatusCode != http.StatusOK {
		t.Fatalf("GET /readyz failed: %v, status: %v", err, respReady.Status)
	}
	_ = respReady.Body.Close()

	// Test /metrics
	respMetrics, err := client.Get(baseURL + "/metrics")
	if err != nil || respMetrics.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics failed: %v, status: %v", err, respMetrics.Status)
	}
	_ = respMetrics.Body.Close()

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

	var info api.ControlPlaneInfoResponse
	if err := proto.Unmarshal(body, &info); err != nil {
		t.Fatalf("failed to unmarshal ControlPlaneInfoResponse: %v", err)
	}
	if info.OidcIssuer != issuer || info.ClientId != "sam-mesh-audience" {
		t.Errorf("unexpected info response claims: %+v", &info)
	}
	if len(info.RouterAddresses) != 0 {
		t.Errorf("expected 0 active routers, got %d", len(info.RouterAddresses))
	}

	// With an explicit OIDC client id, /info must advertise it while the
	// audience stays the first allowed audience.
	t.Run("explicit oidc client id", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "cp-clientid.db")
		st, err := storage.NewSQLStore("sqlite", dbPath)
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}
		defer func() { _ = st.Close() }()

		srv2, err := NewServer(Options{
			DriverName:       "sqlite",
			DataSourceName:   dbPath,
			OIDCIssuer:       issuer,
			OIDCClientID:     "sam-cli-app",
			AllowedAudiences: []string{"sam-mesh-audience"},
		}, st)
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		rec := httptest.NewRecorder()
		srv2.HandleInfo(rec, httptest.NewRequest(http.MethodGet, "/info", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected /info status: %d", rec.Code)
		}
		var info2 api.ControlPlaneInfoResponse
		if err := proto.Unmarshal(rec.Body.Bytes(), &info2); err != nil {
			t.Fatalf("failed to unmarshal ControlPlaneInfoResponse: %v", err)
		}
		if info2.ClientId != "sam-cli-app" || info2.Audience != "sam-mesh-audience" {
			t.Errorf("unexpected client id/audience: %+v", &info2)
		}
	})

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
	roles := []*api.PolicyRole{
		{
			Name:            api.RoleRouter,
			AllowedServices: []string{"*"},
			AllowedTargets:  []string{"*"},
		},
		{
			Name:            "user-role",
			AllowedServices: []string{"mcp:read"},
		},
	}
	bindings := []*api.PolicyBinding{
		{Role: api.RoleRouter, Members: []string{"group:routers"}},
		{Role: "user-role", Members: []string{"group:users"}},
	}
	if err := store.SaveMeshPolicy(ctx, roles, bindings); err != nil {
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

	nodePubKeyBytes, _ := crypto.MarshalPublicKey(privNode.GetPublic())
	enrollNodeReq := &api.EnrollRequest{
		Jwt:           nodeJWT,
		PeerId:        nodePeer.String(),
		PublicKey:     nodePubKeyBytes,
		RequestedRole: api.RoleNode,
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
		"roles":  []string{api.RoleRouter},
	})

	routerPubKeyBytes, _ := crypto.MarshalPublicKey(privRouter.GetPublic())
	enrollRouterReq := &api.EnrollRequest{
		Jwt:           routerJWT,
		PeerId:        routerPeer.String(),
		PublicKey:     routerPubKeyBytes,
		RequestedRole: api.RoleRouter,
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

	var info api.ControlPlaneInfoResponse
	_ = proto.Unmarshal(body, &info)

	if !reflect.DeepEqual(info.RouterAddresses, routerAddresses) {
		t.Errorf("expected active routers address list %v, got %v", routerAddresses, info.RouterAddresses)
	}

	// 5b. Leases that would redirect joiners are refused: malformed
	// multiaddrs and addresses terminating at another peer.
	for name, badAddr := range map[string]string{
		"not a multiaddr": "not-even-a-multiaddr",
		"missing p2p":     "/ip4/203.0.113.66/tcp/4001",
		"foreign peer":    "/ip4/203.0.113.66/tcp/4001/p2p/" + nodePeer.String(),
	} {
		badLease := &api.RouterLeaseRequest{
			PeerId:    routerPeer.String(),
			Addresses: []string{badAddr},
			Biscuit:   enrollRouterResp.BiscuitToken,
		}
		reqData, _ = proto.Marshal(badLease)
		resp, err = client.Post(baseURL+"/routers/lease", "application/x-protobuf", bytes.NewReader(reqData))
		if err != nil {
			t.Fatalf("POST bad lease (%s) failed: %v", name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 for lease with %s, got: %s", name, resp.Status)
		}
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

// The console renders this JSON for editing and posts the result straight back,
// so anything the render drops is silently deleted from the mesh policy on the
// next save. protojson is generated, which is the point: a hand-written renderer
// is what lost custom_datalog before.
func TestMarshalPolicyJSONRoundTrip(t *testing.T) {
	roles := []*api.PolicyRole{
		{
			Name:            "dev",
			AllowedServices: []string{"mcp://git"},
			AllowedTargets:  []string{"node:abc"},
			CustomDatalog:   []string{"right(\"data:read\");"},
		},
		{
			Name:            "ops",
			AllowedServices: []string{"mcp://deploy"},
		},
	}
	bindings := []*api.PolicyBinding{
		{Role: "dev", Members: []string{"group:developers"}},
		{Role: "ops", Members: []string{"user:root"}},
	}

	rendered, err := marshalPolicyJSON(roles, bindings)
	if err != nil {
		t.Fatalf("rendering the policy: %v", err)
	}

	// Proto names, because that is what the docs and the Helm bootstrap job use.
	if !strings.Contains(rendered, "allowed_services") || !strings.Contains(rendered, "custom_datalog") {
		t.Fatalf("rendered policy does not use proto field names:\n%s", rendered)
	}

	// Exactly what the console posts back.
	parsed := &api.PolicyConfigUpdateRequest{}
	if err := protojson.Unmarshal([]byte(rendered), parsed); err != nil {
		t.Fatalf("parsing back the rendered policy: %v\n%s", err, rendered)
	}

	if len(parsed.Roles) != len(roles) {
		t.Fatalf("got %d roles, want %d", len(parsed.Roles), len(roles))
	}
	for i, want := range roles {
		if !proto.Equal(parsed.Roles[i], want) {
			t.Errorf("role %d round-tripped as %v, want %v", i, parsed.Roles[i], want)
		}
	}
	if len(parsed.Bindings) != len(bindings) {
		t.Fatalf("got %d bindings, want %d", len(parsed.Bindings), len(bindings))
	}
	for i, want := range bindings {
		if !proto.Equal(parsed.Bindings[i], want) {
			t.Errorf("binding %d round-tripped as %v, want %v", i, parsed.Bindings[i], want)
		}
	}

	// The result must survive the same validation a POST applies.
	if err := validatePolicyConfig(parsed); err != nil {
		t.Errorf("round-tripped policy failed validation: %v", err)
	}
}

// The console posts the policy editor's contents as protojson, so this is the
// path the only editor a mesh operator has depends on.
func TestPoliciesAcceptConsoleJSON(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	srv.config.AdminToken = "super-secret-admin-token"
	client := &http.Client{Timeout: 5 * time.Second}

	// Proto field names, exactly as the docs and the Helm bootstrap job write them.
	policy := `{
	  "roles": [
	    {
	      "name": "dev",
	      "allowed_services": ["mcp://git"],
	      "allowed_targets": ["group:eng"],
	      "custom_datalog": ["right(\"data:read\");"]
	    }
	  ],
	  "bindings": [{"role": "dev", "members": ["user:bob"]}]
	}`

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/policies", strings.NewReader(policy))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /policies: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /policies as JSON: got %s (body: %s)", resp.Status, body)
	}

	roles, bindings, err := store.GetMeshPolicy(context.Background())
	if err != nil {
		t.Fatalf("reading back the stored policy: %v", err)
	}
	if len(roles) != 1 || roles[0].Name != "dev" {
		t.Fatalf("stored roles = %v, want a single role named dev", roles)
	}
	if len(roles[0].CustomDatalog) != 1 {
		t.Errorf("custom_datalog was dropped on save: %v", roles[0])
	}
	if len(bindings) != 1 || bindings[0].Role != "dev" {
		t.Fatalf("stored bindings = %v, want a single binding for dev", bindings)
	}

	// What /status hands the console must be postable back unchanged.
	rendered, err := marshalPolicyJSON(roles, bindings)
	if err != nil {
		t.Fatalf("rendering the stored policy: %v", err)
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/policies", strings.NewReader(rendered))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("re-posting the rendered policy: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-posting the rendered policy: got %s (body: %s)", resp.Status, body)
	}
}

// A misspelled field is the difference between a permission being granted and
// silently not existing, so it has to be an error rather than a discarded key.
func TestPoliciesRejectUnknownJSONFields(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	srv.config.AdminToken = "super-secret-admin-token"
	client := &http.Client{Timeout: 5 * time.Second}

	for name, policy := range map[string]string{
		"misspelled role field": `{"roles": [{"name": "dev", "allowed_service": ["mcp://git"]}]}`,
		"misspelled top level":  `{"role": [{"name": "dev"}]}`,
		"legacy version key":    `{"version": "v1alpha1", "roles": [{"name": "dev"}]}`,
	} {
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/policies", strings.NewReader(policy))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer super-secret-admin-token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: POST /policies: %v", name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: got status %d, want %d", name, resp.StatusCode, http.StatusBadRequest)
		}
	}

	// Nothing should have been stored by any of those.
	roles, bindings, err := store.GetMeshPolicy(context.Background())
	if err != nil && err != storage.ErrNotFound {
		t.Fatalf("reading back the stored policy: %v", err)
	}
	if len(roles) != 0 || len(bindings) != 0 {
		t.Errorf("a rejected policy was stored anyway: roles=%v bindings=%v", roles, bindings)
	}
}

func TestPoliciesConfigurationREST(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	srv.config.AdminToken = "super-secret-admin-token"
	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Get policies without token (should return 401)
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/policies", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /policies failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated request, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 2. Get policies with incorrect token (should return 401)
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/policies", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /policies failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 3. Get policies with correct token (should return 404 since none exists)
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/policies", nil)
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /policies failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for empty policy, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 4. Put policies (should succeed)
	updateReq := &api.PolicyConfigUpdateRequest{
		Roles: []*api.PolicyRole{
			{
				Name:            "dev",
				AllowedServices: []string{"mcp://git"},
			},
		},
		Bindings: []*api.PolicyBinding{
			{Role: "dev", Members: []string{"group:developers"}},
		},
	}
	reqData, _ := proto.Marshal(updateReq)

	req, _ = http.NewRequest(http.MethodPost, baseURL+"/policies", bytes.NewReader(reqData))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("POST /policies failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected POST /policies status: %s (body: %s)", resp.Status, string(body))
	}
	_ = resp.Body.Close()

	// 5. Get policies again with correct token (verify content)
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/policies", nil)
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err = client.Do(req)
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

	if len(getResp.Roles) == 0 || getResp.Roles[0].Name != "dev" {
		t.Errorf("returned policy content mismatch: %+v", getResp.Roles)
	}
	if len(getResp.Bindings) == 0 || getResp.Bindings[0].Members[0] != "group:developers" {
		t.Errorf("returned policy content mismatch: %+v", getResp.Bindings)
	}
}

func TestEnrollmentWorkflow(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	// Configure admin token
	srv.config.AdminToken = "super-secret-admin-token"

	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Create Bootstrap Token (Manual Approval Gate)
	srv.config.AutoApproveEnrollment = false

	adminReqBody := []byte(`{
		"role": "sam:role:router",
		"ttl_hours": 2,
		"max_usages": 2,
		"description": "Test Mode B"
	}`)

	req, _ := http.NewRequest("POST", baseURL+"/admin/bootstrap-tokens", bytes.NewBuffer(adminReqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to create bootstrap token: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected status creating token: %s", resp.Status)
	}

	var tokenDetails struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tokenDetails)
	_ = resp.Body.Close()

	if tokenDetails.Token == "" || tokenDetails.ID == "" {
		t.Fatalf("empty token details received: %+v", tokenDetails)
	}

	// Generate Client node key
	privNode, pubNode, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	pID, _ := peer.IDFromPrivateKey(privNode)
	pubBytes, _ := crypto.MarshalPublicKey(pubNode)

	// 2. Submit Enrollment Request (Mode B -> PENDING)
	enrollTS, enrollSig := enrollPoP(t, privNode, pID.String())
	enrollReq := &api.BootstrapEnrollRequest{
		BootstrapToken:     tokenDetails.Token,
		PeerId:             pID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      api.RoleRouter,
		Timestamp:          enrollTS,
		ChallengeSignature: enrollSig,
	}
	enrollReqData, _ := proto.Marshal(enrollReq)

	resp, err = client.Post(baseURL+"/enroll", "application/x-protobuf", bytes.NewBuffer(enrollReqData))
	if err != nil {
		t.Fatalf("failed to enroll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected enroll status: %s", resp.Status)
	}

	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var enrollResp api.BootstrapEnrollResponse
	if err := proto.Unmarshal(body, &enrollResp); err != nil {
		t.Fatalf("failed to unmarshal enroll response: %v", err)
	}
	if enrollResp.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
		t.Errorf("expected PENDING status, got %v", enrollResp.Status)
	}

	// 3. Poll Enrollment Status -> PENDING (signed by the enrollee's key)
	resp, err = client.Do(signedEnrollStatusRequest(t, baseURL, privNode, pID.String(), time.Now().UnixMilli()))
	if err != nil {
		t.Fatalf("failed to get status: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var statusResp api.BootstrapEnrollResponse
	_ = proto.Unmarshal(body, &statusResp)
	if statusResp.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
		t.Errorf("expected polled status to be PENDING, got %v", statusResp.Status)
	}

	// 4. Admin query list & approve
	req, _ = http.NewRequest("GET", baseURL+"/admin/enrollments", nil)
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var enrollList []storage.EnrollmentRequest
	_ = json.NewDecoder(resp.Body).Decode(&enrollList)
	_ = resp.Body.Close()

	if len(enrollList) != 1 || enrollList[0].PeerID != pID.String() {
		t.Fatalf("unexpected enrollments list: %+v", enrollList)
	}
	reqID := enrollList[0].ID

	// Approve
	req, _ = http.NewRequest("POST", baseURL+"/admin/enrollments/"+reqID+"/approve", nil)
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to approve enrollment: %s", resp.Status)
	}
	_ = resp.Body.Close()

	// 5. Poll Status -> APPROVED & Validate Biscuit
	resp, err = client.Do(signedEnrollStatusRequest(t, baseURL, privNode, pID.String(), time.Now().UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	_ = proto.Unmarshal(body, &statusResp)
	if statusResp.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
		t.Fatalf("expected APPROVED, got %v", statusResp.Status)
	}
	if len(statusResp.BiscuitToken) == 0 {
		t.Fatalf("biscuit token is empty")
	}
	if len(statusResp.ControlPlanePublicKey) == 0 {
		t.Fatalf("control plane public key is empty")
	}

	// Verify Biscuit router rights
	_, cpPub, err := store.GetCurrentKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := biscuit.Unmarshal(statusResp.BiscuitToken)
	if err != nil {
		t.Fatalf("failed to unmarshal biscuit: %v", err)
	}
	authorizer, err := b.Authorizer(cpPub, biscuit.WithWorldOptions(datalog.WithMaxDuration(srv.config.BiscuitTimeout)))
	if err != nil {
		t.Fatal(err)
	}
	checkRelay := biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: api.FactRight, IDs: []biscuit.Term{biscuit.String(api.RightRelay)}},
			},
		},
	}}
	authorizer.AddCheck(checkRelay)
	authorizer.AddPolicy(biscuit.Policy{Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
			Body: []biscuit.Predicate{},
		},
	}, Kind: biscuit.PolicyKindAllow})

	if err := authorizer.Authorize(); err != nil {
		t.Errorf("biscuit validation failed: %v", err)
	}

	// 6. Test Mode A (Auto-Approve)
	srv.config.AutoApproveEnrollment = true

	// Generate new client key
	privNode2, pubNode2, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	pID2, _ := peer.IDFromPrivateKey(privNode2)
	pubBytes2, _ := crypto.MarshalPublicKey(pubNode2)

	enrollTS2, enrollSig2 := enrollPoP(t, privNode2, pID2.String())
	enrollReq2 := &api.BootstrapEnrollRequest{
		BootstrapToken:     tokenDetails.Token, // use remaining usage
		PeerId:             pID2.String(),
		PublicKey:          pubBytes2,
		RequestedRole:      api.RoleRouter,
		Timestamp:          enrollTS2,
		ChallengeSignature: enrollSig2,
	}
	enrollReqData2, _ := proto.Marshal(enrollReq2)

	resp, err = client.Post(baseURL+"/enroll", "application/x-protobuf", bytes.NewBuffer(enrollReqData2))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var enrollResp2 api.BootstrapEnrollResponse
	_ = proto.Unmarshal(body, &enrollResp2)
	if enrollResp2.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
		t.Errorf("expected immediate APPROVED status in Auto-Approve mode, got %v", enrollResp2.Status)
	}
	if len(enrollResp2.BiscuitToken) == 0 {
		t.Error("biscuit token empty in Auto-Approve response")
	}
}

// signedEnrollStatusRequest builds a GET /enroll/status request carrying the
// proof-of-possession challenge headers signed by priv.
func signedEnrollStatusRequest(t *testing.T, baseURL string, priv crypto.PrivKey, peerID string, ts int64) *http.Request {
	t.Helper()
	sig, err := priv.Sign(api.EnrollStatusChallenge(peerID, ts))
	if err != nil {
		t.Fatalf("failed to sign enroll status challenge: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/enroll/status?peer_id="+peerID, nil)
	if err != nil {
		t.Fatalf("failed to build enroll status request: %v", err)
	}
	req.Header.Set(api.HeaderChallengeTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(api.HeaderChallengeSignature, base64.RawURLEncoding.EncodeToString(sig))
	return req
}

// enrollPoP returns the timestamp/challenge_signature pair proving possession
// of priv for a POST /enroll as peerID.
func enrollPoP(t *testing.T, priv crypto.PrivKey, peerID string) (int64, []byte) {
	t.Helper()
	ts := time.Now().UnixMilli()
	sig, err := priv.Sign(api.EnrollChallenge(peerID, ts))
	if err != nil {
		t.Fatalf("failed to sign enroll challenge: %v", err)
	}
	return ts, sig
}

// TestBootstrapEnrollmentRequiresProofOfPossession pins the fix for
// GHSA-hp3x-79wr-rx66 on both bootstrap endpoints: neither GET /enroll/status
// nor a repeated POST /enroll may reveal an enrollment's status or biscuit to
// a caller that cannot sign with the enrollee's key — holding a valid
// bootstrap token is not enough.
func TestBootstrapEnrollmentRequiresProofOfPossession(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	srv.config.AdminToken = "super-secret-admin-token"
	srv.config.AutoApproveEnrollment = true

	client := &http.Client{Timeout: 5 * time.Second}

	adminReqBody := []byte(`{"role": "sam:role:router", "ttl_hours": 2, "max_usages": 2, "description": "PoP test"}`)
	req, _ := http.NewRequest("POST", baseURL+"/admin/bootstrap-tokens", bytes.NewBuffer(adminReqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to create bootstrap token: %v", err)
	}
	var tokenDetails struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tokenDetails)
	_ = resp.Body.Close()
	if tokenDetails.Token == "" {
		t.Fatal("empty bootstrap token")
	}

	priv, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	pID, _ := peer.IDFromPrivateKey(priv)
	pubBytes, _ := crypto.MarshalPublicKey(pub)

	enrollTS, enrollSig := enrollPoP(t, priv, pID.String())
	enrollData, _ := proto.Marshal(&api.BootstrapEnrollRequest{
		BootstrapToken:     tokenDetails.Token,
		PeerId:             pID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      api.RoleRouter,
		Timestamp:          enrollTS,
		ChallengeSignature: enrollSig,
	})
	resp, err = client.Post(baseURL+"/enroll", "application/x-protobuf", bytes.NewReader(enrollData))
	if err != nil {
		t.Fatalf("failed to enroll: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var enrollResp api.BootstrapEnrollResponse
	_ = proto.Unmarshal(body, &enrollResp)
	if enrollResp.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED || len(enrollResp.BiscuitToken) == 0 {
		t.Fatalf("expected auto-approved enrollment with biscuit, got %v", enrollResp.Status)
	}

	otherKey, otherPub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	otherPID, _ := peer.IDFromPrivateKey(otherKey)

	anonReq, _ := http.NewRequest(http.MethodGet, baseURL+"/enroll/status?peer_id="+pID.String(), nil)
	denied := map[string]*http.Request{
		"anonymous poll":  anonReq,
		"wrong key":       signedEnrollStatusRequest(t, baseURL, otherKey, pID.String(), time.Now().UnixMilli()),
		"stale timestamp": signedEnrollStatusRequest(t, baseURL, priv, pID.String(), time.Now().Add(-6*time.Minute).UnixMilli()),
		"unknown peer":    signedEnrollStatusRequest(t, baseURL, otherKey, otherPID.String(), time.Now().UnixMilli()),
	}
	for name, dr := range denied {
		resp, err := client.Do(dr)
		if err != nil {
			t.Fatalf("%s: request failed: %v", name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: expected 401, got %s (body %q)", name, resp.Status, body)
		}
		if bytes.Contains(body, enrollResp.BiscuitToken) {
			t.Errorf("%s: response leaked the enrollment biscuit", name)
		}
	}

	// Positive control: the enrollee itself still collects its biscuit.
	resp, err = client.Do(signedEnrollStatusRequest(t, baseURL, priv, pID.String(), time.Now().UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signed poll failed: %s (body %q)", resp.Status, body)
	}
	var statusResp api.BootstrapEnrollResponse
	if err := proto.Unmarshal(body, &statusResp); err != nil {
		t.Fatalf("failed to unmarshal status response: %v", err)
	}
	if statusResp.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED || !bytes.Equal(statusResp.BiscuitToken, enrollResp.BiscuitToken) {
		t.Fatalf("signed poll did not return the approved biscuit: %v", statusResp.Status)
	}

	// POST /enroll is gated the same way: the existing-enrollment branch
	// re-serves the stored biscuit, so a bootstrap token holder who is not
	// the peer must never reach it.
	postEnroll := func(name string, payload []byte) *api.BootstrapEnrollResponse {
		t.Helper()
		resp, err := client.Post(baseURL+"/enroll", "application/x-protobuf", bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("%s: POST /enroll failed: %v", name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var r api.BootstrapEnrollResponse
		_ = proto.Unmarshal(body, &r)
		return &r
	}

	otherPubBytes, _ := crypto.MarshalPublicKey(otherPub)
	crossTS, crossSig := enrollPoP(t, otherKey, pID.String())
	for name, payload := range map[string]*api.BootstrapEnrollRequest{
		"cross-peer re-fetch with wrong key": {
			BootstrapToken:     tokenDetails.Token,
			PeerId:             pID.String(),
			PublicKey:          pubBytes,
			RequestedRole:      api.RoleRouter,
			Timestamp:          crossTS,
			ChallengeSignature: crossSig,
		},
		"peer_id not derived from public_key": {
			BootstrapToken:     tokenDetails.Token,
			PeerId:             pID.String(),
			PublicKey:          otherPubBytes,
			RequestedRole:      api.RoleRouter,
			Timestamp:          crossTS,
			ChallengeSignature: crossSig,
		},
		"missing challenge": {
			BootstrapToken: tokenDetails.Token,
			PeerId:         pID.String(),
			PublicKey:      pubBytes,
			RequestedRole:  api.RoleRouter,
		},
	} {
		data, _ := proto.Marshal(payload)
		r := postEnroll(name, data)
		if r.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
			t.Errorf("%s: expected REJECTED, got %v", name, r.Status)
		}
		if len(r.BiscuitToken) != 0 {
			t.Errorf("%s: response leaked a biscuit", name)
		}
	}

	// The enrollee itself retries POST /enroll idempotently.
	retryTS, retrySig := enrollPoP(t, priv, pID.String())
	retryData, _ := proto.Marshal(&api.BootstrapEnrollRequest{
		BootstrapToken:     tokenDetails.Token,
		PeerId:             pID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      api.RoleRouter,
		Timestamp:          retryTS,
		ChallengeSignature: retrySig,
	})
	r := postEnroll("enrollee retry", retryData)
	if r.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED || !bytes.Equal(r.BiscuitToken, enrollResp.BiscuitToken) {
		t.Fatalf("enrollee retry did not return its own biscuit: %v", r.Status)
	}

	// Domain separation: a signature captured from one endpoint must verify
	// nowhere else, even signed by the right key within the freshness window.
	crossEndpointTS := time.Now().UnixMilli()
	statusSig, err := priv.Sign(api.EnrollStatusChallenge(pID.String(), crossEndpointTS))
	if err != nil {
		t.Fatal(err)
	}
	replayData, _ := proto.Marshal(&api.BootstrapEnrollRequest{
		BootstrapToken:     tokenDetails.Token,
		PeerId:             pID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      api.RoleRouter,
		Timestamp:          crossEndpointTS,
		ChallengeSignature: statusSig, // valid /enroll/status signature, wrong endpoint
	})
	if r := postEnroll("cross-endpoint replay", replayData); r.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED || len(r.BiscuitToken) != 0 {
		t.Errorf("an /enroll/status signature was accepted at /enroll: %v", r.Status)
	}

	enrollSigForStatus, err := priv.Sign(api.EnrollChallenge(pID.String(), crossEndpointTS))
	if err != nil {
		t.Fatal(err)
	}
	statusReplay, _ := http.NewRequest(http.MethodGet, baseURL+"/enroll/status?peer_id="+pID.String(), nil)
	statusReplay.Header.Set(api.HeaderChallengeTimestamp, strconv.FormatInt(crossEndpointTS, 10))
	statusReplay.Header.Set(api.HeaderChallengeSignature, base64.RawURLEncoding.EncodeToString(enrollSigForStatus))
	resp, err = client.Do(statusReplay)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an /enroll signature was accepted at /enroll/status: %s", resp.Status)
	}
}

// TestEnrollStatusRateLimited pins that /enroll/status shares the enrollment
// rate limit: the advisory's PoC relied on polling it without bound.
func TestEnrollStatusRateLimited(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	limited := false
	for i := 0; i < EnrollBurst+10; i++ {
		resp, err := client.Get(baseURL + "/enroll/status?peer_id=unknown")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatalf("no 429 after %d rapid /enroll/status requests", EnrollBurst+10)
	}
}

// enrollRefreshTestNode enrolls a bootstrap node directly in the store and
// returns its key and currently issued biscuit, ready to drive /refresh.
func enrollRefreshTestNode(t *testing.T, ctx context.Context, store storage.Store) (crypto.PrivKey, []byte) {
	t.Helper()

	cpPriv, _, err := store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}

	priv, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	nodePeer, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	pubKeyBytes, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPublicKey: %v", err)
	}

	biscuitBytes, err := identity.MintBootstrapBiscuitToken(
		cpPriv,
		nodePeer,
		api.RoleNode,
		time.Now().Add(api.BiscuitTokenTTL),
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken: %v", err)
	}

	if err := store.EnrollNode(ctx, &storage.EnrolledNode{
		PeerID:         nodePeer.String(),
		PublicKey:      pubKeyBytes,
		Biscuit:        biscuitBytes,
		Role:           api.RoleNode,
		EnrollmentType: "Bootstrap",
		EnrolledAt:     time.Now(),
		ExpiresAt:      time.Now().Add(api.OIDCSessionTTL),
	}); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}
	return priv, biscuitBytes
}

// signedRefreshRequest builds a marshaled /refresh body for the given timestamp.
func signedRefreshRequest(t *testing.T, priv crypto.PrivKey, timestamp int64) []byte {
	t.Helper()

	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	sig, err := priv.Sign(api.RefreshChallenge(pid.String(), timestamp))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := proto.Marshal(&api.TokenRefreshRequest{
		ChallengeSignature: sig,
		Timestamp:          timestamp,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return data
}

// doRefresh posts a prebuilt /refresh body under the given biscuit and returns
// the response status and body.
func doRefresh(t *testing.T, cpURL string, biscuit, body []byte) (int, []byte) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, cpURL+"/refresh", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(biscuit))
	req.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

// TestHandleRefresh_TimestampFreshness walks the challenge timestamp across
// the ±5m freshness window. Each case enrolls its own node because a
// successful refresh rotates the biscuit and would bleed into the next case.
func TestHandleRefresh_TimestampFreshness(t *testing.T) {
	t.Parallel()

	srv, store, cpURL := setupTestServer(t, "")
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	ctx := context.Background()

	cases := []struct {
		name       string
		timestamp  func() int64
		wantStatus int
	}{
		{"fresh", func() int64 { return time.Now().UnixMilli() }, http.StatusOK},
		{"within window past", func() int64 { return time.Now().Add(-4 * time.Minute).UnixMilli() }, http.StatusOK},
		{"within window future", func() int64 { return time.Now().Add(4 * time.Minute).UnixMilli() }, http.StatusOK},
		{"stale", func() int64 { return time.Now().Add(-2 * time.Hour).UnixMilli() }, http.StatusUnauthorized},
		{"far future", func() int64 { return time.Now().Add(2 * time.Hour).UnixMilli() }, http.StatusUnauthorized},
		{"seconds instead of milliseconds", func() int64 { return time.Now().Unix() }, http.StatusUnauthorized},
		// Absent and malformed timestamps are authentication failures like
		// every other bad challenge: one uniform 401, no oracle.
		{"zero", func() int64 { return 0 }, http.StatusUnauthorized},
		{"negative", func() int64 { return -1 }, http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, biscuitBytes := enrollRefreshTestNode(t, ctx, store)
			status, body := doRefresh(t, cpURL, biscuitBytes, signedRefreshRequest(t, priv, tc.timestamp()))
			if status != tc.wantStatus {
				t.Errorf("got status %d, want %d (body: %s)", status, tc.wantStatus, body)
			}
		})
	}
}

// TestHandleRefresh_BiscuitIsSingleUse pins refresh-token rotation: a biscuit
// can be redeemed exactly once, so a captured request replayed inside the
// freshness window mints nothing, while the rotated token keeps refreshing.
func TestHandleRefresh_BiscuitIsSingleUse(t *testing.T) {
	t.Parallel()

	srv, store, cpURL := setupTestServer(t, "")
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	ctx := context.Background()
	priv, biscuitBytes := enrollRefreshTestNode(t, ctx, store)

	refreshData := signedRefreshRequest(t, priv, time.Now().UnixMilli())

	status, body := doRefresh(t, cpURL, biscuitBytes, refreshData)
	if status != http.StatusOK {
		t.Fatalf("first refresh: got %d: %s", status, body)
	}
	var refreshResp api.TokenRefreshResponse
	if err := proto.Unmarshal(body, &refreshResp); err != nil {
		t.Fatalf("unmarshal TokenRefreshResponse: %v", err)
	}
	if bytes.Equal(refreshResp.BiscuitToken, biscuitBytes) {
		t.Fatal("refresh returned the same biscuit instead of rotating it")
	}

	// Byte-identical replay of the captured request: the timestamp is still
	// fresh, but the presented biscuit has been rotated.
	status, body = doRefresh(t, cpURL, biscuitBytes, refreshData)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected replayed refresh to be rejected with 401, got %d: %s", status, body)
	}

	// The rotated token is the one redeemable credential.
	status, body = doRefresh(t, cpURL, refreshResp.BiscuitToken, signedRefreshRequest(t, priv, time.Now().UnixMilli()))
	if status != http.StatusOK {
		t.Fatalf("refresh with rotated biscuit: got %d: %s", status, body)
	}
}

func TestTokenRefreshAndRevocation(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	srv, store, cpURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	srv.config.AdminToken = "super-secret-admin-token"
	ctx := context.Background()

	// Setup policy configuration in the database
	roles2 := []*api.PolicyRole{}
	bindings2 := []*api.PolicyBinding{
		{Role: api.RoleNode, Members: []string{"group:users"}},
	}
	if err := store.SaveMeshPolicy(ctx, roles2, bindings2); err != nil {
		t.Fatal(err)
	}

	// 1. Enroll client node via OIDC
	privNode, pubNode, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
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

	nodePubKeyBytes, _ := crypto.MarshalPublicKey(pubNode)
	enrollNodeReq := &api.EnrollRequest{
		Jwt:           nodeJWT,
		PeerId:        nodePeer.String(),
		PublicKey:     nodePubKeyBytes,
		RequestedRole: api.RoleNode,
	}
	reqData, _ := proto.Marshal(enrollNodeReq)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(cpURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
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
	biscuitToken := enrollNodeResp.BiscuitToken

	// 2. Perform refresh
	timestamp := time.Now().UnixMilli()
	refreshPID, _ := peer.IDFromPrivateKey(privNode)
	challengeSig, err := privNode.Sign(api.RefreshChallenge(refreshPID.String(), timestamp))
	if err != nil {
		t.Fatalf("failed to generate challenge signature: %v", err)
	}

	refreshReq := &api.TokenRefreshRequest{
		ChallengeSignature: challengeSig,
		Timestamp:          timestamp,
	}
	refreshData, _ := proto.Marshal(refreshReq)

	reqRefresh, _ := http.NewRequest("POST", cpURL+"/refresh", bytes.NewReader(refreshData))
	b64Biscuit := base64.StdEncoding.EncodeToString(biscuitToken)
	reqRefresh.Header.Set("Authorization", "Bearer "+b64Biscuit)
	reqRefresh.Header.Set("Content-Type", "application/x-protobuf")

	resp, err = client.Do(reqRefresh)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("refresh response failure status %s: %s", resp.Status, string(body))
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var refreshResp api.TokenRefreshResponse
	if err := proto.Unmarshal(body, &refreshResp); err != nil {
		t.Fatalf("failed to unmarshal TokenRefreshResponse: %v", err)
	}
	if len(refreshResp.BiscuitToken) == 0 {
		t.Fatal("refreshed biscuit token is empty")
	}

	// 3. Admin Revocation
	revokeReq := &api.TokenRevokeRequest{
		PeerId: nodePeer.String(),
	}
	revokeData, _ := proto.Marshal(revokeReq)

	req, _ := http.NewRequest("POST", cpURL+"/admin/revoke", bytes.NewReader(revokeData))
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	req.Header.Set("Content-Type", "application/x-protobuf")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("admin revoke failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin revoke response status failure: %s (body: %s)", resp.Status, string(body))
	}
	_ = resp.Body.Close()

	// 4. Verify refresh is rejected after revocation
	reqRefreshCompromised, _ := http.NewRequest("POST", cpURL+"/refresh", bytes.NewReader(refreshData))
	reqRefreshCompromised.Header.Set("Authorization", "Bearer "+b64Biscuit)
	reqRefreshCompromised.Header.Set("Content-Type", "application/x-protobuf")

	resp, err = client.Do(reqRefreshCompromised)
	if err != nil {
		t.Fatalf("refresh check failed: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected refresh to be forbidden after revocation, got %s", resp.Status)
	}
	_ = resp.Body.Close()
}

func TestNodeProactiveTokenRefresh(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	srv, store, cpURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	srv.config.AdminToken = "super-secret-admin-token"
	ctx := context.Background()

	// Setup policy configuration in the database
	roles3 := []*api.PolicyRole{}
	bindings3 := []*api.PolicyBinding{
		{Role: api.RoleNode, Members: []string{"group:users"}},
	}
	if err := store.SaveMeshPolicy(ctx, roles3, bindings3); err != nil {
		t.Fatal(err)
	}

	// Generate node keys
	privNode, pubNode, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	nodePeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	nodeJWT := mintToken(map[string]interface{}{
		"sub":    "node-refresh-test",
		"groups": []string{"users"},
	})

	// Enroll via registration endpoint
	nodePubKeyBytes, _ := crypto.MarshalPublicKey(pubNode)
	enrollNodeReq := &api.EnrollRequest{
		Jwt:           nodeJWT,
		PeerId:        nodePeer.String(),
		PublicKey:     nodePubKeyBytes,
		RequestedRole: api.RoleNode,
	}
	reqData, _ := proto.Marshal(enrollNodeReq)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(cpURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
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
	biscuitToken := enrollNodeResp.BiscuitToken

	// Set up local node Store
	tempDir := t.TempDir()
	nStore, err := node.NewStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create node store: %v", err)
	}

	privKeyBytes, err := crypto.MarshalPrivateKey(privNode)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	if err := nStore.SaveKey(privKeyBytes); err != nil {
		t.Fatalf("failed to save private key: %v", err)
	}
	if err := nStore.SaveControlPlaneURL(cpURL); err != nil {
		t.Fatalf("failed to save control plane URL: %v", err)
	}
	if err := nStore.SaveIdentity(biscuitToken); err != nil {
		t.Fatalf("failed to save initial identity: %v", err)
	}
	if err := nStore.SaveIdentityExpiration(enrollNodeResp.Expiration); err != nil {
		t.Fatalf("failed to save initial expiration: %v", err)
	}

	n := &node.SamNode{
		Store: nStore,
	}

	// Trigger proactive refresh
	err = n.RefreshEnrollment(ctx)
	if err != nil {
		t.Fatalf("RefreshEnrollment failed: %v", err)
	}

	// Assert that token and expiration updated
	refreshedToken, err := nStore.LoadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	refreshedExpiration, err := nStore.LoadIdentityExpiration()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(refreshedToken, biscuitToken) {
		t.Error("biscuit token did not change after refresh")
	}
	if refreshedExpiration <= enrollNodeResp.Expiration {
		t.Errorf("expected refreshed expiration %d to be after initial expiration %d", refreshedExpiration, enrollNodeResp.Expiration)
	}
}

func TestAdminPanelAndUI(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	srv.config.AdminToken = "test-admin-pass"

	testUser := &storage.User{
		ID:        "oidc-sub-123",
		Email:     "user@example.com",
		Role:      "user",
		CreatedAt: time.Now(),
	}
	if err := store.SaveUser(context.Background(), testUser); err != nil {
		t.Fatalf("failed to save test user: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Query /admin/status without token -> should fail with 401
	resp, err := client.Get(baseURL + "/admin/status")
	if err != nil {
		t.Fatalf("GET /admin/status failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 status for unauthenticated status query, got: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 2. Query /admin/status with token -> should succeed
	req, _ := http.NewRequest("GET", baseURL+"/admin/status", nil)
	req.Header.Set("Authorization", "Bearer test-admin-pass")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/status failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 status for authenticated status query, got: %d", resp.StatusCode)
	}

	var statusData map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&statusData); err != nil {
		t.Fatalf("failed to decode admin status response: %v", err)
	}
	_ = resp.Body.Close()

	if _, ok := statusData["active_routers"]; !ok {
		t.Error("status response missing active_routers")
	}
	if _, ok := statusData["enrolled_nodes"]; !ok {
		t.Error("status response missing enrolled_nodes")
	}
	if _, ok := statusData["enrollment_requests"]; !ok {
		t.Error("status response missing enrollment_requests")
	}
	if _, ok := statusData["bootstrap_tokens"]; !ok {
		t.Error("status response missing bootstrap_tokens")
	}
	users, ok := statusData["users"].([]any)
	if !ok || len(users) != 1 {
		t.Fatalf("expected 1 user in status response, got: %v", statusData["users"])
	}
	if got := users[0].(map[string]any)["ID"]; got != testUser.ID {
		t.Errorf("expected user ID %q, got %v", testUser.ID, got)
	}

	// 3. Query /admin/ UI page -> should fail with 404 as it is removed
	resp, err = client.Get(baseURL + "/admin/")
	if err != nil {
		t.Fatalf("GET /admin/ failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 status for /admin/ UI page, got: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 4. Query /policies without token -> should fail with 401
	resp, err = client.Get(baseURL + "/policies")
	if err != nil {
		t.Fatalf("GET /policies failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 status for unauthenticated GET /policies, got: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestUserStatusAndTenancy(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	s, store, _ := setupTestServer(t, issuer)
	defer func() { _ = s.Close() }()

	baseURL := "http://" + s.Addr()
	client := &http.Client{}

	userA := &storage.User{
		ID:        "user-a-sub",
		Email:     "user-a@example.com",
		Role:      "user",
		CreatedAt: time.Now(),
	}
	userB := &storage.User{
		ID:        "user-b-sub",
		Email:     "user-b@example.com",
		Role:      "user",
		CreatedAt: time.Now(),
	}
	errUserA := store.SaveUser(context.Background(), userA)
	if errUserA != nil {
		t.Fatalf("SaveUser A failed: %v", errUserA)
	}
	errUserB := store.SaveUser(context.Background(), userB)
	if errUserB != nil {
		t.Fatalf("SaveUser B failed: %v", errUserB)
	}

	nodeA := &storage.EnrolledNode{
		PeerID:    "peer-node-a",
		PublicKey: []byte("pubkey-a"),
		Biscuit:   []byte("dummy-biscuit-a"),
		Role:      "sam:role:node",
		OwnerID:   userA.ID,
	}
	nodeB := &storage.EnrolledNode{
		PeerID:    "peer-node-b",
		PublicKey: []byte("pubkey-b"),
		Biscuit:   []byte("dummy-biscuit-b"),
		Role:      "sam:role:node",
		OwnerID:   userB.ID,
	}
	errNodeA := store.EnrollNode(context.Background(), nodeA)
	if errNodeA != nil {
		t.Fatalf("EnrollNode A failed: %v", errNodeA)
	}
	errNodeB := store.EnrollNode(context.Background(), nodeB)
	if errNodeB != nil {
		t.Fatalf("EnrollNode B failed: %v", errNodeB)
	}

	tokenA := mintToken(map[string]interface{}{
		"iss":   issuer,
		"sub":   userA.ID,
		"email": userA.Email,
		"aud":   "sam-mesh-audience",
	})

	req, _ := http.NewRequest("GET", baseURL+"/user/status", nil)
	req.Header.Set("Authorization", "Bearer "+tokenA)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /user/status failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got: %d", resp.StatusCode)
	}

	var data map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&data)
	_ = resp.Body.Close()

	enrolledNodes, ok := data["enrolled_nodes"].([]interface{})
	if !ok {
		t.Fatal("enrolled_nodes is not an array")
	}
	if len(enrolledNodes) != 1 {
		t.Fatalf("expected 1 node for User A, got: %d", len(enrolledNodes))
	}
	nodeMap := enrolledNodes[0].(map[string]interface{})
	if nodeMap["PeerID"] != "peer-node-a" {
		t.Errorf("expected node 'peer-node-a', got: %s", nodeMap["PeerID"])
	}

	reqRevoke, _ := http.NewRequest("POST", baseURL+"/user/revoke?id=peer-node-b", nil)
	reqRevoke.Header.Set("Authorization", "Bearer "+tokenA)
	respRevoke, err := client.Do(reqRevoke)
	if err != nil {
		t.Fatalf("POST /user/revoke failed: %v", err)
	}
	if respRevoke.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for revoking someone else's node, got: %d", respRevoke.StatusCode)
	}
	_ = respRevoke.Body.Close()

	reqRevokeSelf, _ := http.NewRequest("POST", baseURL+"/user/revoke?id=peer-node-a", nil)
	reqRevokeSelf.Header.Set("Authorization", "Bearer "+tokenA)
	respRevokeSelf, err := client.Do(reqRevokeSelf)
	if err != nil {
		t.Fatalf("POST /user/revoke self failed: %v", err)
	}
	if respRevokeSelf.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for revoking own node, got: %d", respRevokeSelf.StatusCode)
	}
	_ = respRevokeSelf.Body.Close()

	nodeAUpdated, _ := store.GetNode(context.Background(), "peer-node-a")
	if !nodeAUpdated.Banned {
		t.Error("expected node A to be banned/revoked in DB")
	}
}

func TestResolveRolesAndRoleImpersonationProtection(t *testing.T) {
	bindings := []*api.PolicyBinding{
		{
			Role:    api.RoleRouter,
			Members: []string{"group:routers", "role:oidc-router-role"},
		},
		{
			Role:    api.RoleSamBox,
			Members: []string{"user:sambox-admin-sub"},
		},
	}

	t.Run("OIDC claims role is not blindly trusted without explicit binding", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub":   "attacker-sub",
			"roles": []string{api.RoleRouter, api.RoleSamBox, "unbound-role"},
		}
		roles := resolveRoles("peer-123", claims, bindings)
		for _, r := range roles {
			if r == api.RoleRouter || r == api.RoleSamBox {
				t.Errorf("Security flaw: resolveRoles granted capability role %q from raw OIDC claims without explicit binding", r)
			}
		}
	})

	t.Run("Explicit role mapping in binding grants capability role", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub":   "router-sub",
			"roles": []string{"oidc-router-role"},
		}
		roles := resolveRoles("peer-123", claims, bindings)
		hasRouter := false
		for _, r := range roles {
			if r == api.RoleRouter {
				hasRouter = true
			}
		}
		if !hasRouter {
			t.Errorf("Expected role %q to be granted via explicit role binding mapping", api.RoleRouter)
		}
	})

	t.Run("Group membership grants bound capability role", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub":    "router-user",
			"groups": []string{"routers"},
		}
		roles := resolveRoles("peer-456", claims, bindings)
		hasRouter := false
		for _, r := range roles {
			if r == api.RoleRouter {
				hasRouter = true
			}
		}
		if !hasRouter {
			t.Errorf("Expected role %q to be granted via group binding", api.RoleRouter)
		}
	})

	t.Run("User sub grants bound capability role", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "sambox-admin-sub",
		}
		roles := resolveRoles("peer-789", claims, bindings)
		hasSamBox := false
		for _, r := range roles {
			if r == api.RoleSamBox {
				hasSamBox = true
			}
		}
		if !hasSamBox {
			t.Errorf("Expected role %q to be granted via user sub binding", api.RoleSamBox)
		}
	})
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
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
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
}

// TestAuthDenialPaths exercises the negative/rejection paths of the
// zero-trust boundary: malformed input, wrong audience, oversized bodies,
// and bad admin credentials must never reach business logic.
func TestAuthDenialPaths(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	srv.config.AdminToken = "super-secret-admin-token"

	client := &http.Client{Timeout: 5 * time.Second}

	newEnrollBody := func(jwtStr string) []byte {
		privNode, pubNode, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			t.Fatal(err)
		}
		pID, err := peer.IDFromPrivateKey(privNode)
		if err != nil {
			t.Fatal(err)
		}
		pubBytes, _ := crypto.MarshalPublicKey(pubNode)
		reqData, _ := proto.Marshal(&api.EnrollRequest{
			Jwt:           jwtStr,
			PeerId:        pID.String(),
			PublicKey:     pubBytes,
			RequestedRole: api.RoleNode,
		})
		return reqData
	}

	t.Run("malformed protobuf body is rejected", func(t *testing.T) {
		resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader([]byte("not-a-protobuf-message")))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 for malformed protobuf body, got %d", resp.StatusCode)
		}
	})

	t.Run("malformed JWT is rejected", func(t *testing.T) {
		resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(newEnrollBody("not-a-valid-jwt")))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 for malformed JWT, got %d", resp.StatusCode)
		}
	})

	t.Run("wrong audience JWT is rejected", func(t *testing.T) {
		badAudJWT := mintToken(map[string]interface{}{
			"sub": "node-mallory",
			"aud": "some-other-audience",
		})
		resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(newEnrollBody(badAudJWT)))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 for wrong-audience JWT, got %d", resp.StatusCode)
		}
	})

	t.Run("oversized body is rejected", func(t *testing.T) {
		oversized := bytes.Repeat([]byte("a"), maxRequestBodyBytes+1)
		resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(oversized))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("expected oversized body to be rejected, got %d", resp.StatusCode)
		}
	})

	t.Run("admin endpoint rejects wrong token", func(t *testing.T) {
		req, _ := http.NewRequest("GET", baseURL+"/admin/status", nil)
		req.Header.Set("Authorization", "Bearer this-is-not-the-admin-token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 for wrong admin token, got %d", resp.StatusCode)
		}
	})

	t.Run("register rejects role not granted by policy", func(t *testing.T) {
		if err := store.SaveMeshPolicy(context.Background(), nil, []*api.PolicyBinding{
			{Role: api.RoleNode, Members: []string{"group:users"}},
		}); err != nil {
			t.Fatal(err)
		}
		unauthorizedJWT := mintToken(map[string]interface{}{
			"sub":    "node-outsider",
			"groups": []string{"outsiders"},
		})
		reqData := newEnrollBody(unauthorizedJWT)
		var req api.EnrollRequest
		_ = proto.Unmarshal(reqData, &req)
		req.RequestedRole = api.RoleSamBox // not granted to "group:outsiders"
		reqData, _ = proto.Marshal(&req)

		resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 for unauthorized role request, got %d", resp.StatusCode)
		}
	})
}

// TestBootstrapTokenOwnerPropagatesToNode ensures a node enrolled with a user-owned
// bootstrap token is attributed to that user, which is what makes the console's
// per-user node listing work.
func TestBootstrapTokenOwnerPropagatesToNode(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	srv.config.AutoApproveEnrollment = true

	ctx := context.Background()
	client := &http.Client{Timeout: 5 * time.Second}

	const ownerSub = "owner-sub-id"
	userJWT := mintToken(map[string]interface{}{"sub": ownerSub, "email": "owner@example.com"})

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/user/bootstrap-tokens",
		bytes.NewBufferString(`{"role":"`+api.RoleNode+`","max_usages":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+userJWT)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to create bootstrap token: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("unexpected status creating token: %s (%s)", resp.Status, body)
	}
	var tokenDetails struct {
		Token   string `json:"token"`
		OwnerID string `json:"owner_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tokenDetails)
	_ = resp.Body.Close()

	if tokenDetails.OwnerID != ownerSub {
		t.Fatalf("token owner = %q, want %q", tokenDetails.OwnerID, ownerSub)
	}

	privNode, pubNode, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	pID, _ := peer.IDFromPrivateKey(privNode)
	pubBytes, _ := crypto.MarshalPublicKey(pubNode)

	ownerTS, ownerSig := enrollPoP(t, privNode, pID.String())
	enrollData, _ := proto.Marshal(&api.BootstrapEnrollRequest{
		BootstrapToken:     tokenDetails.Token,
		PeerId:             pID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      api.RoleNode,
		Timestamp:          ownerTS,
		ChallengeSignature: ownerSig,
	})
	resp, err = client.Post(baseURL+"/enroll", "application/x-protobuf", bytes.NewBuffer(enrollData))
	if err != nil {
		t.Fatalf("failed to enroll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("unexpected enroll status: %s (%s)", resp.Status, body)
	}
	_ = resp.Body.Close()

	enrolled, err := store.GetNode(ctx, pID.String())
	if err != nil {
		t.Fatalf("failed to load enrolled node: %v", err)
	}
	if enrolled.OwnerID != ownerSub {
		t.Errorf("enrolled node owner = %q, want %q", enrolled.OwnerID, ownerSub)
	}
}
