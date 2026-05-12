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
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
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
		services: NewServiceRegistry(d),
		DHT:      d,
	}

	// MCPService.Init() opens a live session to the URL; serve a fake MCP backend.
	upstream := httptest.NewServer(newFakeMCPHandler(t, []*mcp.Tool{}))
	defer upstream.Close()

	reqBody := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "test-service", Description: "test desc"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: upstream.URL},
	}
	body, err := protojson.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	req := httptest.NewRequest("POST", "/sam/service/register", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	handleRegisterService(node, rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d, body: %s", rr.Code, rr.Body.String())
	}

	if !node.IsServiceRegistered("test-service") {
		t.Errorf("expected service to be registered")
	}

	// Tear down so the live MCP session releases the upstream SSE stream;
	// otherwise upstream.Close() blocks waiting for in-flight handlers.
	if err := node.UnregisterService(context.Background(), "test-service"); err != nil {
		t.Errorf("unregister: %v", err)
	}
}

func TestHandleUnregisterService(t *testing.T) {
	node := &SamNode{
		services: NewServiceRegistry(&fakeDHT{}),
	}
	node.services.insertService(&testService{info: &api.ServiceInfo{Name: "test-service"}})

	reqBody := &api.ServiceInfo{Name: "test-service"}
	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

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

func TestHandleDiscoverService(t *testing.T) {
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

	node := &SamNode{
		services:      NewServiceRegistry(d),
		DHT:           d,
		Host:          h,
		BoundHTTPAddr: "127.0.0.1:8080",
	}

	// Register a service on another host to be discovered
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

	serviceInfo := &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "remote-service"}
	c, err := serviceNameToCID(serviceInfo.Type, serviceInfo.Name)
	if err != nil {
		t.Fatal(err)
	}
	// We don't strictly need Provide to succeed if we can mock the DHT lookup,
	// but here we are using real DHT. If it fails because table is empty,
	// we might need to ensure routing table is populated.
	// Let's ignore the error for now to see if it works without it (maybe DHT cache works).
	_ = d2.Provide(context.Background(), c, true)

	time.Sleep(100 * time.Millisecond) // Wait for DHT

	req := httptest.NewRequest("GET", "/sam/service/discover?type=mcp&name=remote-service", nil)
	rr := httptest.NewRecorder()

	handleDiscoverService(node, rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d, body: %s", rr.Code, rr.Body.String())
	}

	var providers []*api.DiscoveredProvider
	if err := json.NewDecoder(rr.Body).Decode(&providers); err != nil {
		t.Fatal(err)
	}

	if len(providers) != 1 {
		t.Errorf("expected 1 provider, got %d", len(providers))
	} else if providers[0].PeerId != h2.ID().String() {
		t.Errorf("expected provider %s, got %s", h2.ID().String(), providers[0].PeerId)
	}
}

func TestListLocalServices(t *testing.T) {
	node := &SamNode{
		services: NewServiceRegistry(&fakeDHT{}),
	}

	service1 := &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "service1"}
	service2 := &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: "service2"}

	node.services.insertService(&testService{info: service1})
	node.services.insertService(&testService{info: service2})

	services := node.ListLocalServices(api.ServiceType_SERVICE_TYPE_UNSPECIFIED)

	if len(services) != 2 {
		t.Errorf("expected 2 services, got %d", len(services))
	}
}

func TestListLocalServices_TypeFilter(t *testing.T) {
	node := &SamNode{
		services: NewServiceRegistry(&fakeDHT{}),
	}
	mcpA := &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "mcp-a"}
	mcpB := &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "mcp-b"}
	inf := &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: "inf-a"}
	node.services.insertService(&testService{info: mcpA})
	node.services.insertService(&testService{info: mcpB})
	node.services.insertService(&testService{info: inf})

	cases := []struct {
		name      string
		filter    api.ServiceType
		wantCount int
	}{
		{"unspecified returns all", api.ServiceType_SERVICE_TYPE_UNSPECIFIED, 3},
		{"mcp filter", api.ServiceType_SERVICE_TYPE_MCP, 2},
		{"inference filter", api.ServiceType_SERVICE_TYPE_INFERENCE, 1},
		{"a2a filter (none registered)", api.ServiceType_SERVICE_TYPE_A2A, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := node.ListLocalServices(tc.filter)
			if len(got) != tc.wantCount {
				t.Errorf("expected %d services, got %d", tc.wantCount, len(got))
			}
			for _, s := range got {
				if tc.filter != api.ServiceType_SERVICE_TYPE_UNSPECIFIED && s.Type != tc.filter {
					t.Errorf("filter %v leaked service of type %v: %s", tc.filter, s.Type, s.Name)
				}
			}
		})
	}
}

func TestServiceTypeToCID_Properties(t *testing.T) {
	mcp1, err := serviceTypeToCID(api.ServiceType_SERVICE_TYPE_MCP)
	if err != nil {
		t.Fatal(err)
	}
	mcp2, err := serviceTypeToCID(api.ServiceType_SERVICE_TYPE_MCP)
	if err != nil {
		t.Fatal(err)
	}
	if !mcp1.Equals(mcp2) {
		t.Errorf("serviceTypeToCID is non-deterministic: %s vs %s", mcp1, mcp2)
	}

	inf, err := serviceTypeToCID(api.ServiceType_SERVICE_TYPE_INFERENCE)
	if err != nil {
		t.Fatal(err)
	}
	if mcp1.Equals(inf) {
		t.Errorf("expected distinct CIDs for distinct types, both = %s", mcp1)
	}

	named, err := serviceNameToCID(api.ServiceType_SERVICE_TYPE_MCP, "some-service")
	if err != nil {
		t.Fatal(err)
	}
	if mcp1.Equals(named) {
		t.Errorf("type-only CID collided with name-keyed CID: %s", mcp1)
	}

	if _, err := serviceTypeToCID(api.ServiceType_SERVICE_TYPE_UNSPECIFIED); err == nil {
		t.Errorf("expected error for unspecified type")
	}
}

// TestServiceKeyToCID_Equivalence pins the wire format: the public
// helpers must compose into the same CID as a direct call to the
// shared key builder, so optimizing the helpers later can't silently
// shift the DHT keys.
func TestServiceKeyToCID_Equivalence(t *testing.T) {
	gotName, err := serviceNameToCID(api.ServiceType_SERVICE_TYPE_MCP, "svc")
	if err != nil {
		t.Fatal(err)
	}
	wantName, err := serviceKeyToCID("mcp", "svc")
	if err != nil {
		t.Fatal(err)
	}
	if !gotName.Equals(wantName) {
		t.Errorf("serviceNameToCID != serviceKeyToCID: %s vs %s", gotName, wantName)
	}

	gotType, err := serviceTypeToCID(api.ServiceType_SERVICE_TYPE_MCP)
	if err != nil {
		t.Fatal(err)
	}
	wantType, err := serviceKeyToCID("mcp")
	if err != nil {
		t.Fatal(err)
	}
	if !gotType.Equals(wantType) {
		t.Errorf("serviceTypeToCID != serviceKeyToCID: %s vs %s", gotType, wantType)
	}
}

func TestHandleRegisterService_Validation(t *testing.T) {
	node := &SamNode{
		services: NewServiceRegistry(&fakeDHT{}),
	}

	tests := []struct {
		name           string
		reqBody        *api.RegisterServiceRequest
		expectedStatus int
	}{
		{
			name: "Missing service",
			reqBody: &api.RegisterServiceRequest{
				Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: "http://localhost:8080"},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Missing name",
			reqBody: &api.RegisterServiceRequest{
				Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP},
				Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: "http://localhost:8080"},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Unspecified type",
			reqBody: &api.RegisterServiceRequest{
				Service: &api.ServiceInfo{Name: "test-service", Type: api.ServiceType_SERVICE_TYPE_UNSPECIFIED},
				Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: "http://localhost:8080"},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Missing backend",
			reqBody: &api.RegisterServiceRequest{
				Service: &api.ServiceInfo{Name: "test-service", Type: api.ServiceType_SERVICE_TYPE_MCP},
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := protojson.Marshal(tt.reqBody)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "/sam/service/register", bytes.NewBuffer(body))
			rr := httptest.NewRecorder()

			handleRegisterService(node, rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d, body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestStartSidecarServer_TokenMandatory(t *testing.T) {
	node := &SamNode{}

	// Test case: No token, no TLS
	err := startSidecarServer(node, "127.0.0.1:0", "", "", "", "")
	if err == nil {
		t.Fatal("Expected startSidecarServer to fail without token and TLS, but it succeeded")
	}
	if !strings.Contains(err.Error(), "token is mandatory when not using mTLS") {
		t.Fatalf("Expected error to contain 'token is mandatory when not using mTLS', got: %v", err)
	}

	// Test case: Token provided, should not fail immediately
	err = startSidecarServer(node, "127.0.0.1:0", "some-token", "", "", "")
	if err != nil {
		if strings.Contains(err.Error(), "token is mandatory when not using mTLS") {
			t.Fatalf("Did not expect 'token is mandatory' error when token is provided, got: %v", err)
		}
	}
}

func TestRegisterService_PopulatesAggregatedTools(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tools := []*mcp.Tool{
		{Name: "do_thing", Description: "x", InputSchema: map[string]any{"type": "object"}},
	}
	handler := newFakeMCPHandler(t, tools)
	hostedSrv := httptest.NewServer(handler)
	defer hostedSrv.Close()

	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewSamNode(ctx, priv, nil, nil, store, "test-mesh", "1s",
		[]string{"/ip4/127.0.0.1/tcp/0"}, false, &NodeConfigComplete{}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = node.Teardown() }()

	req := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "svc"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: hostedSrv.URL},
	}
	_ = node.RegisterService(ctx, req) // DHT.Provide may fail in isolated test; aggregation is independent.

	svc, ok := node.services.Get("svc")
	if !ok {
		t.Fatal("service was not stored in registry")
	}
	mcpSvc, ok := svc.(*MCPService)
	if !ok {
		t.Fatalf("expected *MCPService, got %T", svc)
	}
	aggregated := mcpSvc.Tools()
	if len(aggregated) != 1 {
		t.Fatalf("expected 1 aggregated tool, got %d", len(aggregated))
	}
	if got := aggregated[0].Name; got != "svc.do_thing" {
		t.Errorf("aggregated tool name: got %q, want %q", got, "svc.do_thing")
	}
}

func TestUnregisterService_DetachesAggregation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tools := []*mcp.Tool{
		{Name: "do_thing", Description: "x", InputSchema: map[string]any{"type": "object"}},
	}
	handler := newFakeMCPHandler(t, tools)
	hostedSrv := httptest.NewServer(handler)
	defer hostedSrv.Close()

	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewSamNode(ctx, priv, nil, nil, store, "test-mesh", "1s",
		[]string{"/ip4/127.0.0.1/tcp/0"}, false, &NodeConfigComplete{}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = node.Teardown() }()

	req := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "svc"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: hostedSrv.URL},
	}
	_ = node.RegisterService(ctx, req)

	svc, ok := node.services.Get("svc")
	if !ok {
		t.Fatal("expected service registered")
	}
	mcpSvc, ok := svc.(*MCPService)
	if !ok {
		t.Fatalf("expected *MCPService, got %T", svc)
	}
	if mcpSvc.session == nil {
		t.Fatal("expected active MCP session before unregister")
	}

	if err := node.UnregisterService(ctx, "svc"); err != nil {
		t.Fatalf("UnregisterService: %v", err)
	}

	if mcpSvc.session != nil {
		t.Error("session should be nil after Unregister")
	}
	if mcpSvc.Tools() != nil {
		t.Error("aggregatedTools should be nil after Unregister")
	}
	if _, stillThere := node.services.Get("svc"); stillThere {
		t.Error("service should be removed from registry")
	}
}
