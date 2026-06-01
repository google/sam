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
	"encoding/json"
	"google.golang.org/protobuf/encoding/protojson"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestServiceDiscovery(t *testing.T) {
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

	// Connect Node B to Node A (to ensure they are in same network)
	// We use the multiplexed HTTP address for MCP calls too!
	callMCP(t, actualApiAddrB, "connect_peer", map[string]any{"peer_addr": addrA})

	// Wait for DHT to have peers on Node A
	t.Log("Waiting for DHT to have peers on Node A...")
	deadline := time.Now().Add(10 * time.Second)
	var dhtReady bool
	for time.Now().Before(deadline) {
		respData := callMCP(t, actualApiAddrA, "get_mesh_info", map[string]any{})
		var data map[string]any
		if err := json.Unmarshal([]byte(respData), &data); err == nil {
			dhtSize, _ := data["dht_size"].(float64)
			if dhtSize > 0 {
				dhtReady = true
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !dhtReady {
		t.Fatalf("DHT not ready on Node A (size 0)")
	}

	// Agent A registers a service
	serviceName := "mcp:github-tools"
	registerService(t, actualApiAddrA, apiToken, serviceName)

	// Wait for DHT propagation
	t.Log("Waiting for DHT propagation...")
	time.Sleep(2 * time.Second)

	// Agent B queries the DHT via Sidecar API
	t.Log("Agent B discovering service...")
	providers := discoverService(t, actualApiAddrB, apiToken, serviceName)

	if len(providers) == 0 {
		t.Fatalf("Agent B failed to discover any providers for %s", serviceName)
	}

	// Verify Agent A is in the providers list
	peerIDA := getPeerIDFromAddr(addrA)
	found := false
	for _, p := range providers {
		if p.ID == peerIDA {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("Agent B did not discover Agent A as provider. Providers: %v", providers)
	}

	// Agent A unregisters the service
	unregisterService(t, actualApiAddrA, apiToken, serviceName)

	t.Log("Service discovery test passed.")
}

func TestServiceDiscoveryStreaming(t *testing.T) {
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

	// Connect Node B to Node A
	callMCP(t, actualApiAddrB, "connect_peer", map[string]any{"peer_addr": addrA})

	// Wait for DHT to have peers on Node A
	t.Log("Waiting for DHT to have peers on Node A...")
	deadline := time.Now().Add(10 * time.Second)
	var dhtReady bool
	for time.Now().Before(deadline) {
		respData := callMCP(t, actualApiAddrA, "get_mesh_info", map[string]any{})
		var data map[string]any
		if err := json.Unmarshal([]byte(respData), &data); err == nil {
			dhtSize, _ := data["dht_size"].(float64)
			if dhtSize > 0 {
				dhtReady = true
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !dhtReady {
		t.Fatalf("DHT not ready on Node A")
	}

	// Agent A registers a service
	serviceName := "mcp:github-tools"
	registerService(t, actualApiAddrA, apiToken, serviceName)

	// Wait for DHT propagation
	t.Log("Waiting for DHT propagation...")
	time.Sleep(2 * time.Second)

	// Call streaming endpoint with invalid timeout first to verify validation
	t.Log("Testing invalid timeout query parameter...")
	badReq, _ := http.NewRequest("GET", "http://"+actualApiAddrB+"/sam/service/discover?type=mcp&name="+serviceName+"&stream=true&timeout=invalid", nil)
	badReq.Header.Set("Authorization", "Bearer "+apiToken)
	badResp, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected StatusBadRequest for invalid timeout, got %d", badResp.StatusCode)
	}

	// Agent B queries the streaming endpoint via HTTP Sidecar
	t.Log("Agent B discovering service via SSE stream...")
	req, _ := http.NewRequest("GET", "http://"+actualApiAddrB+"/sam/service/discover?type=mcp&name="+serviceName+"&stream=true&timeout=5s", nil)
	req.Header.Set("Authorization", "Bearer "+apiToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to request streaming discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Streaming discovery failed with status: %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/event-stream") {
		t.Fatalf("Expected Content-Type text/event-stream, got %q", contentType)
	}

	// Parse stream chunk-by-chunk
	reader := bufio.NewReader(resp.Body)
	peerIDA := getPeerIDFromAddr(addrA)
	var foundStreamed bool

	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read SSE line: %v", err)
		}

		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data:") {
			dataContent := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if dataContent == "{}" {
				continue // Done event or keep-alive empty JSON
			}
			var provider api.DiscoveredProvider
			if err := json.Unmarshal([]byte(dataContent), &provider); err == nil {
				if provider.PeerId == peerIDA.String() {
					foundStreamed = true
				}
			}
		}
		if strings.HasPrefix(line, "event: done") {
			break
		}
	}

	if !foundStreamed {
		t.Fatalf("Failed to stream and find provider Node A in SSE results")
	}

	// Agent A unregisters the service
	unregisterService(t, actualApiAddrA, apiToken, serviceName)
}

func waitForAPI(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for API at %s", addr)
}

func registerService(t *testing.T, apiAddr, token, serviceName string) {
	t.Helper()
	reqData := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{
			Type:        api.ServiceType_SERVICE_TYPE_MCP,
			Name:        serviceName,
			Description: "test desc",
		},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: "http://localhost:8080"},
	}
	body, err := protojson.Marshal(reqData)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "http://"+apiAddr+"/sam/service/register", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to register service: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Register service failed with status: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}
}

func unregisterService(t *testing.T, apiAddr, token, serviceName string) {
	t.Helper()
	reqBody := map[string]string{"Name": serviceName}
	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "http://"+apiAddr+"/sam/service/unregister", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to unregister service: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Unregister service failed with status: %d", resp.StatusCode)
	}
}

func discoverService(t *testing.T, apiAddr, token, serviceName string) []peer.AddrInfo {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+apiAddr+"/sam/service/discover?type=mcp&name="+serviceName, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to discover service: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Discover service failed with status: %d", resp.StatusCode)
	}

	var providers []api.DiscoveredProvider
	if err := json.NewDecoder(resp.Body).Decode(&providers); err != nil {
		t.Fatalf("Failed to decode providers: %v", err)
	}

	var addrInfos []peer.AddrInfo
	for i := range providers {
		p := &providers[i]
		pid, err := peer.Decode(p.PeerId)
		if err != nil {
			t.Logf("Failed to decode peer ID %s: %v", p.PeerId, err)
			continue
		}
		addrInfos = append(addrInfos, peer.AddrInfo{ID: pid})
	}
	return addrInfos
}

func getPeerIDFromAddr(addr string) peer.ID {
	parts := strings.Split(addr, "/p2p/")
	if len(parts) < 2 {
		return ""
	}
	p, _ := peer.Decode(parts[1])
	return p
}
