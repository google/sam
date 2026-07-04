package node

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestDatapathIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Setup: Create two in-memory nodes (Node A and Node B)
	privA, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	privB, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)

	dirA := t.TempDir()
	dirB := t.TempDir()

	storeA, err := NewStore(dirA)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := storeA.Close(); err != nil {
			t.Logf("failed to close storeA: %v", err)
		}
	}()

	storeB, err := NewStore(dirB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := storeB.Close(); err != nil {
			t.Logf("failed to close storeB: %v", err)
		}
	}()

	// Pre-populate stores with dummy keys to avoid enrollment failure if required
	// For this test, we assume we can run without full enrollment if we bypass AuthHandler

	nodeA, err := NewSamNode(Options{
		PrivKey:           privA,
		HubAddrs:          nil,
		Store:             storeA,
		MeshID:            "test-mesh",
		DiscoveryInterval: "1s",
		ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
		EnableRelay:       false,
		NodeConfig:        &NodeConfigComplete{},
		KeyGracePeriod:    24 * time.Hour,
		AllowLoopback:     true,
		MonitorBootstrap:  2 * time.Minute,
		MonitorInterval:   1 * time.Minute,
		BiscuitTimeout:    500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := nodeA.Host.Close(); err != nil {
			t.Logf("failed to close nodeA host: %v", err)
		}
	}()

	nodeB, err := NewSamNode(Options{
		PrivKey:           privB,
		HubAddrs:          nil,
		Store:             storeB,
		MeshID:            "test-mesh",
		DiscoveryInterval: "1s",
		ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
		EnableRelay:       false,
		NodeConfig:        &NodeConfigComplete{},
		KeyGracePeriod:    24 * time.Hour,
		AllowLoopback:     true,
		MonitorBootstrap:  2 * time.Minute,
		MonitorInterval:   1 * time.Minute,
		BiscuitTimeout:    500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := nodeB.Host.Close(); err != nil {
			t.Logf("failed to close nodeB host: %v", err)
		}
	}()

	// Setup identity for Node B (the caller proxy) and trust it on Node A
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen root: %v", err)
	}
	if err := buildAndSaveBiscuit(nodeB, rootPriv); err != nil {
		t.Fatalf("buildAndSaveBiscuit: %v", err)
	}
	nodeA.keysMu.Lock()
	nodeA.trustedKeys = append(nodeA.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
	nodeA.keysMu.Unlock()

	// Connect Node B to Node A directly
	err = nodeB.Host.Connect(ctx, peer.AddrInfo{ID: nodeA.Host.ID(), Addrs: nodeA.Host.Addrs()})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Target Service: On Node A, start a dummy HTTP server
	expectedHeaderValue := "test-value"
	expectedBody := `{"status":"success"}`

	dummyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only assert the test header on the actual proxied request; MCP aggregation
		// probes use other paths (/sse, /message) and don't carry it.
		if r.URL.Path == "/api/v1/test" && r.Header.Get("X-Test-Header") != expectedHeaderValue {
			t.Errorf("Expected header X-Test-Header to be %s, got %s", expectedHeaderValue, r.Header.Get("X-Test-Header"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(expectedBody))
	}))
	defer dummyServer.Close()

	// 3. Registration: Node A registers this dummy server in its ServiceRegistry
	serviceName := "dummy-tool"
	serviceInfo := &api.ServiceInfo{
		Type: api.ServiceType_SERVICE_TYPE_MCP,
		Name: serviceName,
	}

	// We register it in the DHT and also setup the local handler.
	// We ignore the error because DHT Provide might fail if routing table is empty in this isolated test.
	_ = nodeA.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: serviceInfo,
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: dummyServer.URL},
	})

	// Manually add to services map to ensure it's registered for the test lookup
	// because RegisterService might have failed due to DHT not being ready in this isolated test.
	targetURL, _ := url.Parse(dummyServer.URL)
	nodeA.services.insertService(&testService{
		info:    serviceInfo,
		handler: httputil.NewSingleHostReverseProxy(targetURL),
	})

	// Start the Sidecar server for Node B to get BoundHTTPAddr populated
	// We don't need full sidecar for Node B in this test if we call createEgressProxy directly,
	// but let's populate BoundHTTPAddr to avoid nil panics if used.
	nodeB.BoundHTTPAddr = "127.0.0.1:0" // Dummy

	// 4. Execution: Node B makes a request via its local Egress Proxy

	// We need to create the egress proxy for Node B.
	// The user request says: "Implement a reverse proxy on the local `sam-node` HTTP server that intercepts requests to `/sam/`"
	// In sidecar.go we have `createEgressProxy(node)`. We can use it here.

	proxyHandler := createEgressProxy(nodeB)

	// We start a test server for Node B's proxy to simulate the local agent calling it.
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	// Construct the URL targeting Node A's service
	// http://localhost:<port>/sam/{peer_id}/{service_type}/{service_name}/{upstream_path}
	url := fmt.Sprintf("%s/sam/%s/mcp/%s/api/v1/test", proxyServer.URL, nodeA.Host.ID().String(), serviceName)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-Header", expectedHeaderValue)

	client := &http.Client{}

	pidStr := nodeA.Host.ID().String()
	_, err = peer.Decode(pidStr)
	if err != nil {
		t.Fatalf("Failed to decode generated peer ID %s: %v", pidStr, err)
	}

	// Wait for DHT/routing to settle or just retry a few times if needed.
	// Since we connected directly, it should work immediately if the protocol is registered.

	var resp *http.Response
	for i := 0; i < 3; i++ {
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		t.Logf("Attempt %d failed: %v, status: %v", i+1, err, resp)
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("failed to close response body: %v", err)
		}
	}()

	// 5. Assertions
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(bodyBytes) != expectedBody {
		t.Fatalf("Expected body %s, got %s", expectedBody, string(bodyBytes))
	}
}

func TestDatapathIntegration_Unauthenticated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	privA, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	privB, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)

	dirA := t.TempDir()
	dirB := t.TempDir()

	storeA, err := NewStore(dirA)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = storeA.Close() }()

	storeB, err := NewStore(dirB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = storeB.Close() }()

	nodeA, err := NewSamNode(Options{
		PrivKey:           privA,
		HubAddrs:          nil,
		Store:             storeA,
		MeshID:            "test-mesh",
		DiscoveryInterval: "1s",
		ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
		EnableRelay:       false,
		NodeConfig:        &NodeConfigComplete{},
		KeyGracePeriod:    24 * time.Hour,
		AllowLoopback:     true,
		MonitorBootstrap:  2 * time.Minute,
		MonitorInterval:   1 * time.Minute,
		BiscuitTimeout:    500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := nodeA.Host.Close(); err != nil {
			t.Logf("failed to close nodeA host: %v", err)
		}
	}()

	nodeB, err := NewSamNode(Options{
		PrivKey:           privB,
		HubAddrs:          nil,
		Store:             storeB,
		MeshID:            "test-mesh",
		DiscoveryInterval: "1s",
		ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
		EnableRelay:       false,
		NodeConfig:        &NodeConfigComplete{},
		KeyGracePeriod:    24 * time.Hour,
		AllowLoopback:     true,
		MonitorBootstrap:  2 * time.Minute,
		MonitorInterval:   1 * time.Minute,
		BiscuitTimeout:    500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := nodeB.Host.Close(); err != nil {
			t.Logf("failed to close nodeB host: %v", err)
		}
	}()

	// NOTE: We do NOT setup an identity for Node B (caller).
	// This means the Egress Proxy will not inject an X-Sam-Biscuit header,
	// and the request should be rejected by Node A's ingress server.

	// Connect Node B to Node A directly
	err = nodeB.Host.Connect(ctx, peer.AddrInfo{ID: nodeA.Host.ID(), Addrs: nodeA.Host.Addrs()})
	if err != nil {
		t.Fatal(err)
	}

	dummyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer dummyServer.Close()

	serviceName := "dummy-tool"
	serviceInfo := &api.ServiceInfo{
		Type: api.ServiceType_SERVICE_TYPE_MCP,
		Name: serviceName,
	}

	_ = nodeA.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: serviceInfo,
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: dummyServer.URL},
	})

	targetURL, _ := url.Parse(dummyServer.URL)
	nodeA.services.insertService(&testService{
		info:    serviceInfo,
		handler: httputil.NewSingleHostReverseProxy(targetURL),
	})

	nodeB.BoundHTTPAddr = "127.0.0.1:0"

	proxyHandler := createEgressProxy(nodeB)
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	url := fmt.Sprintf("%s/sam/%s/mcp/%s/api/v1/test", proxyServer.URL, nodeA.Host.ID().String(), serviceName)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{}

	var resp *http.Response
	for i := 0; i < 3; i++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		t.Logf("Attempt %d failed: %v", i+1, err)
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// ASSERTION: Should be service unavailable because the local node has no identity to send
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Expected status ServiceUnavailable (503), got %d", resp.StatusCode)
	}
}

func TestStdioDatapathIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Setup: Create two in-memory nodes (Node A and Node B)
	privA, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	privB, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)

	dirA := t.TempDir()
	dirB := t.TempDir()

	storeA, err := NewStore(dirA)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = storeA.Close() }()

	storeB, err := NewStore(dirB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = storeB.Close() }()

	nodeA, err := NewSamNode(Options{
		PrivKey:           privA,
		HubAddrs:          nil,
		Store:             storeA,
		MeshID:            "test-mesh",
		DiscoveryInterval: "1s",
		ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
		EnableRelay:       false,
		NodeConfig:        &NodeConfigComplete{},
		KeyGracePeriod:    24 * time.Hour,
		AllowLoopback:     true,
		MonitorBootstrap:  2 * time.Minute,
		MonitorInterval:   1 * time.Minute,
		BiscuitTimeout:    500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nodeA.Host.Close() }()

	nodeB, err := NewSamNode(Options{
		PrivKey:           privB,
		HubAddrs:          nil,
		Store:             storeB,
		MeshID:            "test-mesh",
		DiscoveryInterval: "1s",
		ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
		EnableRelay:       false,
		NodeConfig:        &NodeConfigComplete{},
		KeyGracePeriod:    24 * time.Hour,
		AllowLoopback:     true,
		MonitorBootstrap:  2 * time.Minute,
		MonitorInterval:   1 * time.Minute,
		BiscuitTimeout:    500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nodeB.Host.Close() }()

	// Setup identity for Node B (the caller proxy) and trust it on Node A
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen root: %v", err)
	}
	if err := buildAndSaveBiscuit(nodeB, rootPriv); err != nil {
		t.Fatalf("buildAndSaveBiscuit: %v", err)
	}
	nodeA.keysMu.Lock()
	nodeA.trustedKeys = append(nodeA.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
	nodeA.keysMu.Unlock()

	// Connect Node B to Node A directly
	err = nodeB.Host.Connect(ctx, peer.AddrInfo{ID: nodeA.Host.ID(), Addrs: nodeA.Host.Addrs()})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Target Service: Register a stdio service on Node A using 'cat'
	serviceName := "stdio-tool"
	serviceInfo := &api.ServiceInfo{
		Type: api.ServiceType_SERVICE_TYPE_MCP,
		Name: serviceName,
	}

	req := &api.RegisterServiceRequest{
		Service: serviceInfo,
		Backend: &api.RegisterServiceRequest_Command{
			Command: &api.CommandBackend{
				Command: []string{"cat"},
			},
		},
	}

	// Manually add to services map to ensure it's registered for the test lookup
	// and avoid double start by not calling RegisterService.
	handler, cmd, err := createStdioBridgeHandler(req.Backend.(*api.RegisterServiceRequest_Command).Command)
	if err != nil {
		t.Fatal(err)
	}
	nodeA.services.insertService(&testService{
		info:    serviceInfo,
		handler: handler,
	})

	defer func() {
		_ = nodeA.UnregisterService(ctx, serviceName)
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	// Start the Sidecar server for Node B to get BoundHTTPAddr populated
	nodeB.BoundHTTPAddr = "127.0.0.1:0" // Dummy

	// 3. Execution: Node B makes requests via its local Egress Proxy
	proxyHandler := createEgressProxy(nodeB)
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	// Construct URLs
	// http://localhost:<port>/sam/{peer_id}/{service_type}/{service_name}/{upstream_path}
	sseURL := fmt.Sprintf("%s/sam/%s/mcp/%s/", proxyServer.URL, nodeA.Host.ID().String(), serviceName)
	postURL := fmt.Sprintf("%s/sam/%s/mcp/%s/", proxyServer.URL, nodeA.Host.ID().String(), serviceName)

	client := &http.Client{}

	// Wait for DHT/routing to settle (retry mechanism)
	var sseResp *http.Response
	for i := 0; i < 3; i++ {
		sseResp, err = client.Get(sseURL)
		if err == nil && sseResp.StatusCode == http.StatusOK {
			break
		}
		t.Logf("SSE Connect Attempt %d failed: %v, status: %v", i+1, err, sseResp)
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sseResp.Body.Close() }()

	if sseResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected SSE status OK, got %d", sseResp.StatusCode)
	}

	// Send a message via POST
	testMessage := `{"jsonrpc":"2.0","method":"ping","id":1}`
	postResp, err := client.Post(postURL, "application/json", bytes.NewBufferString(testMessage))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = postResp.Body.Close() }()

	if postResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected POST status OK, got %d", postResp.StatusCode)
	}

	// Read from SSE stream
	reader := bufio.NewReader(sseResp.Body)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}

	expectedPrefix := "data: "
	if !strings.HasPrefix(line, expectedPrefix) {
		t.Fatalf("Expected line to start with %q, got %q", expectedPrefix, line)
	}

	receivedMessage := strings.TrimPrefix(line, expectedPrefix)
	receivedMessage = strings.TrimSpace(receivedMessage)

	if receivedMessage != testMessage {
		t.Fatalf("Expected to receive %q, got %q", testMessage, receivedMessage)
	}

	// Cancel context to close the SSE stream and allow server to close gracefully
	cancel()
}

func TestDatapathHeadersAndRoutingTable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	privA, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	privB, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)

	dirA := t.TempDir()
	dirB := t.TempDir()

	storeA, err := NewStore(dirA)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = storeA.Close() }()

	storeB, err := NewStore(dirB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = storeB.Close() }()

	nodeA, err := NewSamNode(Options{
		PrivKey:           privA,
		HubAddrs:          nil,
		Store:             storeA,
		MeshID:            "test-mesh",
		DiscoveryInterval: "1s",
		ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
		EnableRelay:       false,
		NodeConfig:        &NodeConfigComplete{},
		KeyGracePeriod:    24 * time.Hour,
		AllowLoopback:     true,
		MonitorBootstrap:  2 * time.Minute,
		MonitorInterval:   1 * time.Minute,
		BiscuitTimeout:    500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := nodeA.Host.Close(); err != nil {
			t.Logf("failed to close nodeA host: %v", err)
		}
	}()

	nodeB, err := NewSamNode(Options{
		PrivKey:           privB,
		HubAddrs:          nil,
		Store:             storeB,
		MeshID:            "test-mesh",
		DiscoveryInterval: "1s",
		ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
		EnableRelay:       false,
		NodeConfig:        &NodeConfigComplete{},
		KeyGracePeriod:    24 * time.Hour,
		AllowLoopback:     true,
		MonitorBootstrap:  2 * time.Minute,
		MonitorInterval:   1 * time.Minute,
		BiscuitTimeout:    500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := nodeB.Host.Close(); err != nil {
			t.Logf("failed to close nodeB host: %v", err)
		}
	}()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen root: %v", err)
	}
	if err := buildAndSaveBiscuit(nodeB, rootPriv); err != nil {
		t.Fatalf("buildAndSaveBiscuit: %v", err)
	}
	nodeA.keysMu.Lock()
	nodeA.trustedKeys = append(nodeA.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
	nodeA.keysMu.Unlock()

	err = nodeB.Host.Connect(ctx, peer.AddrInfo{ID: nodeA.Host.ID(), Addrs: nodeA.Host.Addrs()})
	if err != nil {
		t.Fatal(err)
	}

	// We will record the HTTP request headers and URL received by the backend dummy service.
	var lastReceivedHeaders http.Header
	var lastReceivedPath string

	dummyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastReceivedHeaders = r.Header.Clone()
		lastReceivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer dummyServer.Close()

	serviceName := "dummy-tool"
	serviceInfo := &api.ServiceInfo{
		Type: api.ServiceType_SERVICE_TYPE_MCP,
		Name: serviceName,
	}

	_ = nodeA.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: serviceInfo,
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: dummyServer.URL},
	})

	handler, err := newReverseProxyHandler(dummyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	nodeA.services.insertService(&testService{
		info:    serviceInfo,
		handler: handler,
	})

	nodeB.BoundHTTPAddr = "127.0.0.1:0"

	proxyHandler := createEgressProxy(nodeB)
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	client := &http.Client{}

	tests := []struct {
		name                   string
		pathSuffix             string // e.g. "/api/v1/test" or ""
		requestHeaders         map[string]string
		wantReceivedHeaders    map[string]string // header key -> expected value. If value is "", header must be absent.
		wantReceivedPathSuffix string
	}{
		{
			name:       "Auth mapping with X-Sam-Authorization",
			pathSuffix: "/api/v1/test",
			requestHeaders: map[string]string{
				"Authorization":            "Bearer local-token",
				api.HeaderSamAuthorization: "Bearer upstream-token",
				"X-Test-Request":           "yes",
			},
			wantReceivedHeaders: map[string]string{
				"Authorization":              "Bearer upstream-token",
				api.HeaderSamAuthorization:   "", // Must be stripped
				api.HeaderSamBiscuit:         "", // Must be stripped
				api.HeaderSamNoTrailingSlash: "", // Must be stripped
				"X-Test-Request":             "yes",
			},
			wantReceivedPathSuffix: "/api/v1/test",
		},
		{
			name:       "Auth stripping when X-Sam-Authorization is absent",
			pathSuffix: "/api/v1/test",
			requestHeaders: map[string]string{
				"Authorization":  "Bearer local-token",
				"X-Test-Request": "yes",
			},
			wantReceivedHeaders: map[string]string{
				"Authorization":              "", // Must be stripped to avoid leaking local sidecar token
				api.HeaderSamAuthorization:   "",
				api.HeaderSamBiscuit:         "",
				api.HeaderSamNoTrailingSlash: "",
				"X-Test-Request":             "yes",
			},
			wantReceivedPathSuffix: "/api/v1/test",
		},
		{
			name:       "Trailing slash handling with empty path",
			pathSuffix: "", // Requesting the root of the service: .../dummy-tool
			requestHeaders: map[string]string{
				"Authorization": "Bearer local-token",
			},
			wantReceivedHeaders: map[string]string{
				api.HeaderSamNoTrailingSlash: "", // Must be stripped
			},
			wantReceivedPathSuffix: "/", // Should be mapped to "/" without trailing slash issues
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lastReceivedHeaders = nil
			lastReceivedPath = ""

			url := fmt.Sprintf("%s/sam/%s/mcp/%s%s", proxyServer.URL, nodeA.Host.ID().String(), serviceName, tt.pathSuffix)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range tt.requestHeaders {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("Expected 200 OK, got %d", resp.StatusCode)
			}

			// Verify received path
			if lastReceivedPath != tt.wantReceivedPathSuffix {
				t.Errorf("Expected received path to be %q, got %q", tt.wantReceivedPathSuffix, lastReceivedPath)
			}

			// Verify received headers
			for k, expectedVal := range tt.wantReceivedHeaders {
				actualVal := lastReceivedHeaders.Get(k)
				if expectedVal == "" {
					if _, present := lastReceivedHeaders[k]; present {
						t.Errorf("Expected header %q to be absent, but got %q", k, actualVal)
					}
				} else {
					if actualVal != expectedVal {
						t.Errorf("Expected header %q to be %q, got %q", k, expectedVal, actualVal)
					}
				}
			}
		})
	}
}
