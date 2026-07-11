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

package router

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/controlplane"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/storage"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
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

func setupControlPlane(t *testing.T, oidcIssuer string) (*controlplane.Server, storage.Store, string) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "control-plane.db")

	store, err := storage.NewSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	opts := controlplane.Options{
		ListenAddr:            "127.0.0.1:0", // Auto-allocate
		DriverName:            "sqlite",
		DataSourceName:        dbPath,
		OIDCIssuer:            oidcIssuer,
		AllowedAudiences:      []string{"sam-mesh-audience"},
		LeaseDuration:         5 * time.Second,
		KeyRotationInterval:   12 * time.Hour,
		KeyGracePeriod:        10 * time.Minute,
		InsecureSkipTLSVerify: true,
		BiscuitTimeout:        1 * time.Second,
	}

	// Bootstrap Policy granting 'router' role to group 'routers'
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
				AllowedServices: []string{"mcp://read"},
			},
		},
	}
	if err := store.SavePolicy(context.Background(), policy); err != nil {
		t.Fatalf("failed to save policy: %v", err)
	}

	srv, err := controlplane.NewServer(opts, store)
	if err != nil {
		t.Fatalf("failed to create CP server: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start CP: %v", err)
	}

	return srv, store, "http://" + srv.Addr()
}

func TestRouterIntegration(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	cp, cpStore, cpURL := setupControlPlane(t, issuer)
	defer func() {
		_ = cp.Close()
		_ = cpStore.Close()
	}()

	tempDir := t.TempDir()
	routerKeyPath := filepath.Join(tempDir, "router.key")

	routerJWT := mintToken(map[string]interface{}{
		"sub":    "router-1",
		"groups": []string{"routers"},
	})

	// 1. Create and Start Router
	rOpts := Options{
		ControlPlaneURL:    cpURL,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
		KeysSyncInterval:   2 * time.Second,
		LeaseRenewInterval: 2 * time.Second,
		OIDCToken:          routerJWT,
		KeysDBPath:         routerKeyPath,
		AllowLoopback:      true,
		BiscuitTimeout:     1 * time.Second,
	}

	r, err := NewRouter(context.Background(), rOpts)
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}

	if err := r.Start(); err != nil {
		t.Fatalf("failed to start router: %v", err)
	}
	defer func() { _ = r.Close() }()

	// Verify lease renewal populated the database
	time.Sleep(3 * time.Second) // wait for lease renewal loop to fire
	activeRouters, err := cpStore.GetActiveRouters(context.Background())
	if err != nil {
		t.Fatalf("failed to get active routers from store: %v", err)
	}
	if len(activeRouters) != 1 {
		t.Fatalf("expected 1 active router in DB, got %d", len(activeRouters))
	}
	if activeRouters[0].PeerID != r.Host.ID().String() {
		t.Errorf("router peer ID mismatch in DB lease")
	}

	// 2. Perform client connection and Mutual Auth Handshake
	// Boot a client node and register it on control plane to get a Biscuit
	nodeJWT := mintToken(map[string]interface{}{
		"sub":    "node-user-1",
		"groups": []string{"users"},
	})

	nodeKeyPath := filepath.Join(tempDir, "node.key")
	nodePrivKey, err := getOrGeneratePeerKey(nodeKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	nodePeerID, _ := peer.IDFromPrivateKey(nodePrivKey)

	// Fetch biscuit for client node via Control Plane HTTP client
	client := &http.Client{Timeout: 5 * time.Second}
	enrollNodeReq := &api.EnrollRequest{
		Jwt:    nodeJWT,
		PeerId: nodePeerID.String(),
	}
	reqData, _ := proto.Marshal(enrollNodeReq)
	resp, err := client.Post(cpURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var enrollNodeResp api.EnrollResponse
	_ = proto.Unmarshal(body, &enrollNodeResp)

	// Now create a client libp2p Host
	clientHost, err := libp2p.New(
		libp2p.Identity(nodePrivKey),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientHost.Close() }()

	// Connect to Router
	routerAddr := r.Host.Addrs()[0]
	routerInfo, err := peer.AddrInfoFromP2pAddr(routerAddr.Encapsulate(multiaddr.StringCast("/p2p/" + r.Host.ID().String())))
	if err != nil {
		t.Fatal(err)
	}

	if err := clientHost.Connect(context.Background(), *routerInfo); err != nil {
		t.Fatalf("failed to connect client to router: %v", err)
	}

	// Open mutual auth stream
	s, err := clientHost.NewStream(context.Background(), routerInfo.ID, api.AuthProtocolID)
	if err != nil {
		t.Fatalf("failed to open auth stream: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Send Node Biscuit
	writer := msgio.NewVarintWriter(s)
	authFrame := &api.AuthFrame{Biscuit: enrollNodeResp.BiscuitToken}
	data, _ := proto.Marshal(authFrame)
	if err := writer.WriteMsg(data); err != nil {
		t.Fatalf("failed to write auth frame: %v", err)
	}

	// Read Router response
	reader := msgio.NewVarintReaderSize(s, 1024*64)
	respMsg, err := reader.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	defer reader.ReleaseMsg(respMsg)

	var authResp api.AuthResponse
	if err := proto.Unmarshal(respMsg, &authResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !authResp.Success {
		t.Fatalf("mutual auth rejected: %s", authResp.Error)
	}

	// Verify Router Biscuit
	// Fetch CP public keys to verify router biscuit
	validKeys, _ := cpStore.GetAllValidKeys(context.Background())
	var cpPubKeys []ed25519.PublicKey
	for _, k := range validKeys {
		cpPubKeys = append(cpPubKeys, k.Public)
	}

	_, err = identity.VerifyBiscuit(authResp.Biscuit, r.Host.ID(), cpPubKeys, 1*time.Second)
	if err != nil {
		t.Fatalf("failed client-side verification of router biscuit: %v", err)
	}

	t.Log("Mutual Authentication completed successfully!")
}

func TestRouterFederation(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	cp, cpStore, cpURL := setupControlPlane(t, issuer)
	defer func() {
		_ = cp.Close()
		_ = cpStore.Close()
	}()

	tempDir := t.TempDir()

	// Mint token for Router 1
	router1JWT := mintToken(map[string]interface{}{
		"sub":    "router-1",
		"groups": []string{"routers"},
	})
	// Mint token for Router 2
	router2JWT := mintToken(map[string]interface{}{
		"sub":    "router-2",
		"groups": []string{"routers"},
	})

	r1KeyPath := filepath.Join(tempDir, "router1.key")
	r1, err := NewRouter(context.Background(), Options{
		ControlPlaneURL:    cpURL,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
		KeysSyncInterval:   2 * time.Second,
		LeaseRenewInterval: 2 * time.Second,
		OIDCToken:          router1JWT,
		KeysDBPath:         r1KeyPath,
		AllowLoopback:      true,
		BiscuitTimeout:     1 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r1.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r1.Close() }()

	r2KeyPath := filepath.Join(tempDir, "router2.key")
	r2, err := NewRouter(context.Background(), Options{
		ControlPlaneURL:    cpURL,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
		KeysSyncInterval:   2 * time.Second,
		LeaseRenewInterval: 2 * time.Second,
		OIDCToken:          router2JWT,
		KeysDBPath:         r2KeyPath,
		AllowLoopback:      true,
		BiscuitTimeout:     1 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r2.Close() }()

	// Wait for both routers to renew their lease so they are both in control plane DB
	time.Sleep(3 * time.Second)

	// Trigger connection sync manually to form the federation link
	r1.connectBootstrapRouters()
	r2.connectBootstrapRouters()

	// Wait a moment for stream handshakes to complete
	time.Sleep(1 * time.Second)

	// Assert that Router 1 connected to Router 2
	if len(r1.Host.Network().ConnsToPeer(r2.Host.ID())) == 0 {
		t.Errorf("Router 1 is not connected to Router 2")
	}

	// Assert that Router 1 mutually authenticated Router 2
	if _, authenticated := r1.authenticatedPeers.Load(r2.Host.ID()); !authenticated {
		t.Errorf("Router 2 is not authenticated in Router 1's peers")
	}

	// Assert that Router 2 mutually authenticated Router 1
	if _, authenticated := r2.authenticatedPeers.Load(r1.Host.ID()); !authenticated {
		t.Errorf("Router 1 is not authenticated in Router 2's peers")
	}
}
