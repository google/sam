package main

import (
	"bufio"
	"bytes"
	"context"
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

	nodeA, err := NewSamNode(ctx, privA, nil, nil, storeA, "test-mesh", "1s", []string{"/ip4/127.0.0.1/tcp/0"}, false, &NodeConfigComplete{}, 24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := nodeA.Host.Close(); err != nil {
			t.Logf("failed to close nodeA host: %v", err)
		}
	}()

	nodeB, err := NewSamNode(ctx, privB, nil, nil, storeB, "test-mesh", "1s", []string{"/ip4/127.0.0.1/tcp/0"}, false, &NodeConfigComplete{}, 24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := nodeB.Host.Close(); err != nil {
			t.Logf("failed to close nodeB host: %v", err)
		}
	}()

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

	nodeA, err := NewSamNode(ctx, privA, nil, nil, storeA, "test-mesh", "1s", []string{"/ip4/127.0.0.1/tcp/0"}, false, &NodeConfigComplete{}, 24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nodeA.Host.Close() }()

	nodeB, err := NewSamNode(ctx, privB, nil, nil, storeB, "test-mesh", "1s", []string{"/ip4/127.0.0.1/tcp/0"}, false, &NodeConfigComplete{}, 24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nodeB.Host.Close() }()

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
