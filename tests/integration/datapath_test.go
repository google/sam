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

package integration_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestIntegrationStdioDatapath(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	_, hubAddr := startMockLibp2pHub(t)

	homeA := t.TempDir()
	homeB := t.TempDir()

	apiToken := "secret-token"

	// Start Node A
	t.Log("Starting Node A...")
	_ = startBackgroundNode(t, nodeBin, hubAddr, homeA,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--discovery-interval", "100ms",
		"--bind-addr", "127.0.0.1:0",
		"--api-token", apiToken,
	)

	// Start Node B
	t.Log("Starting Node B...")
	_ = startBackgroundNode(t, nodeBin, hubAddr, homeB,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--discovery-interval", "100ms",
		"--bind-addr", "127.0.0.1:0",
		"--api-token", apiToken,
	)

	// Resolve actual addresses from logs
	actualApiAddrA := waitForMCPAddr(t, filepath.Join(homeA, "node.log"))
	actualApiAddrB := waitForMCPAddr(t, filepath.Join(homeB, "node.log"))

	// Wait for nodes to start sidecar API
	waitForAPI(t, actualApiAddrA)
	waitForAPI(t, actualApiAddrB)

	addrA := waitForPeerInfoInLog(t, filepath.Join(homeA, "node.log"))
	peerIDA := getPeerIDFromAddr(addrA)

	// Connect Node B to Node A
	callMCP(t, actualApiAddrB, "connect_peer", map[string]any{"peer_addr": addrA})

	// Register Stdio service on Node A
	serviceName := "stdio-tool"
	reqData := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{
			Type:        api.ServiceType_SERVICE_TYPE_MCP,
			Name:        serviceName,
			Description: "test stdio service",
		},
		Backend: &api.RegisterServiceRequest_Command{
			Command: &api.CommandBackend{
				Command: []string{"cat"},
			},
		},
	}
	body, err := protojson.Marshal(reqData)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("POST", "http://"+actualApiAddrA+"/sam/service/register", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to register service: %d", resp.StatusCode)
	}

	// Wait for propagation (optional, but safe)
	time.Sleep(1 * time.Second)

	// Node B calls Node A's service via its local egress proxy
	// URL format: http://localhost:<port>/sam/{peer_id}/{service_type}/{service_name}/{upstream_path}
	sseURL := fmt.Sprintf("http://%s/sam/%s/mcp/%s/", actualApiAddrB, peerIDA, serviceName)
	postURL := fmt.Sprintf("http://%s/sam/%s/mcp/%s/", actualApiAddrB, peerIDA, serviceName)

	client := &http.Client{}

	// Establish SSE stream
	var sseResp *http.Response
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("GET", sseURL, nil)
		req.Header.Set("Authorization", "Bearer "+apiToken)
		sseResp, err = client.Do(req)
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

	// Send message via POST
	testMessage := `{"jsonrpc":"2.0","method":"ping","id":1}`
	postReq, _ := http.NewRequest("POST", postURL, bytes.NewBufferString(testMessage))
	postReq.Header.Set("Authorization", "Bearer "+apiToken)
	postReq.Header.Set("Content-Type", "application/json")
	postResp, err := client.Do(postReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = postResp.Body.Close()

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
}

func TestIntegrationHTTPDatapath(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	_, hubAddr := startMockLibp2pHub(t)

	homeA := t.TempDir()
	homeB := t.TempDir()

	apiToken := "secret-token"

	// Start Node A
	t.Log("Starting Node A...")
	_ = startBackgroundNode(t, nodeBin, hubAddr, homeA,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--discovery-interval", "100ms",
		"--bind-addr", "127.0.0.1:0",
		"--api-token", apiToken,
	)

	// Start Node B
	t.Log("Starting Node B...")
	_ = startBackgroundNode(t, nodeBin, hubAddr, homeB,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--discovery-interval", "100ms",
		"--bind-addr", "127.0.0.1:0",
		"--api-token", apiToken,
	)

	// Resolve actual addresses from logs
	actualApiAddrA := waitForMCPAddr(t, filepath.Join(homeA, "node.log"))
	actualApiAddrB := waitForMCPAddr(t, filepath.Join(homeB, "node.log"))

	// Wait for nodes to start sidecar API
	waitForAPI(t, actualApiAddrA)
	waitForAPI(t, actualApiAddrB)

	addrA := waitForPeerInfoInLog(t, filepath.Join(homeA, "node.log"))
	peerIDA := getPeerIDFromAddr(addrA)

	// Connect Node B to Node A
	callMCP(t, actualApiAddrB, "connect_peer", map[string]any{"peer_addr": addrA})

	// Start a dummy HTTP server on Node A's host (simulating local service)
	expectedBody := `{"status":"success"}`
	dummyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(expectedBody))
	}))
	defer dummyServer.Close()

	// Register HTTP service on Node A
	serviceName := "http-tool"
	reqData := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{
			Type:        api.ServiceType_SERVICE_TYPE_MCP,
			Name:        serviceName,
			Description: "test http service",
		},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: dummyServer.URL},
	}
	body, err := protojson.Marshal(reqData)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("POST", "http://"+actualApiAddrA+"/sam/service/register", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to register service: %d", resp.StatusCode)
	}

	// Wait for propagation
	time.Sleep(1 * time.Second)

	// Node B calls Node A's service via its local egress proxy
	url := fmt.Sprintf("http://%s/sam/%s/mcp/%s/testpath", actualApiAddrB, peerIDA, serviceName)

	client := &http.Client{}
	var httpResp *http.Response
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+apiToken)
		httpResp, err = client.Do(req)
		if err == nil && httpResp.StatusCode == http.StatusOK {
			break
		}
		t.Logf("HTTP Connect Attempt %d failed: %v, status: %v", i+1, err, httpResp)
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", httpResp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(bodyBytes) != expectedBody {
		t.Fatalf("Expected body %s, got %s", expectedBody, string(bodyBytes))
	}
}
