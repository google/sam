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
	"fmt"
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

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/storage"
	"github.com/google/sam/internal/node"
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
			{Role: api.RoleRouter, Members: []string{"group:routers"}},
			{Role: "user-role", Members: []string{"group:users"}},
		},
		Roles: map[string]api.RolePolicy{
			api.RoleRouter: {
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

	nodePubKeyBytes, _ := crypto.MarshalPublicKey(privNode.GetPublic())
	enrollNodeReq := &api.EnrollRequest{
		Jwt:       nodeJWT,
		PeerId:    nodePeer.String(),
		PublicKey: nodePubKeyBytes,
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

	routerPubKeyBytes, _ := crypto.MarshalPublicKey(privRouter.GetPublic())
	enrollRouterReq := &api.EnrollRequest{
		Jwt:       routerJWT,
		PeerId:    routerPeer.String(),
		PublicKey: routerPubKeyBytes,
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
	enrollReq := &api.BootstrapEnrollRequest{
		BootstrapToken: tokenDetails.Token,
		PeerId:         pID.String(),
		PublicKey:      pubBytes,
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

	// 3. Poll Enrollment Status -> PENDING
	resp, err = client.Get(baseURL + "/enroll/status?peer_id=" + pID.String())
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
	resp, err = client.Get(baseURL + "/enroll/status?peer_id=" + pID.String())
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

	// Verify Biscuit router rights
	_, cpPub, err := store.GetCurrentKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := biscuit.Unmarshal(statusResp.BiscuitToken)
	if err != nil {
		t.Fatalf("failed to unmarshal biscuit: %v", err)
	}
	authorizer, err := b.Authorizer(cpPub)
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

	enrollReq2 := &api.BootstrapEnrollRequest{
		BootstrapToken: tokenDetails.Token, // use remaining usage
		PeerId:         pID2.String(),
		PublicKey:      pubBytes2,
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
	policy := &api.PolicyConfig{
		Version: "v1alpha1",
		Bindings: []api.Binding{
			{Role: api.RoleNode, Members: []string{"group:users"}},
		},
	}
	if err := store.SavePolicy(ctx, policy); err != nil {
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
		Jwt:       nodeJWT,
		PeerId:    nodePeer.String(),
		PublicKey: nodePubKeyBytes,
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
	challengeData := []byte(fmt.Sprintf("%d", timestamp))
	challengeSig, err := privNode.Sign(challengeData)
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
	policy := &api.PolicyConfig{
		Version: "v1alpha1",
		Bindings: []api.Binding{
			{Role: api.RoleNode, Members: []string{"group:users"}},
		},
	}
	if err := store.SavePolicy(ctx, policy); err != nil {
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
		Jwt:       nodeJWT,
		PeerId:    nodePeer.String(),
		PublicKey: nodePubKeyBytes,
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
	if err := nStore.SaveHubURL(cpURL); err != nil {
		t.Fatalf("failed to save hub URL: %v", err)
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
