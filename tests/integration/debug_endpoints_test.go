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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/sam/api"
)

// connectPeerWithToken dials POST /debug/connect-peer, the REST endpoint that
// replaced the connect_peer MCP tool (#318).
func connectPeerWithToken(t *testing.T, apiAddr, token, peerAddr string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"peer_addr": peerAddr})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+apiAddr+"/debug/connect-peer", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(api.HeaderSamAuthentication, "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("connect-peer request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect-peer returned %s: %s", resp.Status, respBody)
	}
}

func connectPeer(t *testing.T, apiAddr, peerAddr string) {
	t.Helper()
	connectPeerWithToken(t, apiAddr, "test-token", peerAddr)
}

// debugGet fetches one GET /debug endpoint and returns its JSON body.
func debugGet(t *testing.T, apiAddr, path string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+apiAddr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(api.HeaderSamAuthentication, "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned %s: %s", path, resp.Status, respBody)
	}
	return string(respBody)
}

func TestDebugEndpoints(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")

	tmpDir := t.TempDir()

	// Create a mock policy file
	policyFile := filepath.Join(tmpDir, "policies.yaml")
	policyContent := `bindings:
  - members: ["user:mock-user"]
    role: sam:role:node
roles: []
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	oidcURL, mintToken := startCustomMockOIDC(t)
	httpPortCP, cleanupCP := startControlPlaneAndRouter(t, tmpDir, oidcURL, mintToken, policyFile)
	defer cleanupCP()

	fetchPeerID(t, httpPortCP)

	controlPlaneURL := fmt.Sprintf("http://127.0.0.1:%d", httpPortCP)
	apiToken := "test-token"

	homeA := t.TempDir()
	homeB := t.TempDir()

	nodeJWT := mintToken(map[string]interface{}{
		"sub":   "mock-user",
		"roles": []string{api.RoleNode},
	})

	// Start Node A
	t.Log("Starting Node A...")
	nodeA := startBackgroundNode(t, nodeBin, controlPlaneURL, homeA,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--api-token-path", tokenPath(t, apiToken),
		"--jwt", nodeJWT,
	)

	// Start Node B
	t.Log("Starting Node B...")
	nodeB := startBackgroundNode(t, nodeBin, controlPlaneURL, homeB,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--api-token-path", tokenPath(t, apiToken),
		"--jwt", nodeJWT,
	)

	actualApiAddrA := nodeA.waitForAPI(t)
	actualApiAddrB := nodeB.waitForAPI(t)

	addrA := nodeA.p2pAddr

	// Connect Node B to Node A directly; exercises POST /debug/connect-peer
	connectPeer(t, actualApiAddrB, addrA)

	t.Run("mesh-info", func(t *testing.T) {
		resp := debugGet(t, actualApiAddrA, "/debug/mesh-info")
		var info map[string]any
		if err := json.Unmarshal([]byte(resp), &info); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}
		if _, ok := info["connected_peers"]; !ok {
			t.Errorf("expected connected_peers, got %v", info)
		}
		if routerPeerID, ok := info["router_peer_id"].(string); !ok || routerPeerID == "" {
			t.Errorf("expected router_peer_id, got %v", info)
		}
	})

	t.Run("token-info", func(t *testing.T) {
		resp := debugGet(t, actualApiAddrA, "/debug/token-info")
		var info map[string]any
		if err := json.Unmarshal([]byte(resp), &info); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}
		if hasToken, ok := info["has_token"].(bool); !ok || !hasToken {
			t.Errorf("expected has_token=true, got %v", info)
		}
		if _, ok := info["expires_in_seconds"].(float64); !ok {
			t.Errorf("expected expires_in_seconds to exist, got %v", info)
		}
	})

	t.Run("network-info", func(t *testing.T) {
		resp := debugGet(t, actualApiAddrA, "/debug/network-info")
		if !strings.Contains(resp, `"announced_addresses"`) {
			t.Fatalf("network info response does not contain announced_addresses: %s", resp)
		}
		if strings.Contains(resp, `"observed_addresses"`) {
			t.Fatalf("network info response still contains observed_addresses: %s", resp)
		}

		var info map[string]any
		if err := json.Unmarshal([]byte(resp), &info); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}
		if addresses, ok := info["listen_addresses"].([]any); !ok || len(addresses) == 0 {
			t.Errorf("expected listen_addresses array, got %v", info)
		}
		if addresses, ok := info["announced_addresses"].([]any); !ok || len(addresses) == 0 {
			t.Errorf("expected announced_addresses array, got %v", info)
		}
	})

	t.Run("connectivity", func(t *testing.T) {
		resp := debugGet(t, actualApiAddrA, "/debug/connectivity")
		var info map[string]any
		if err := json.Unmarshal([]byte(resp), &info); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}
		if routerLatency, ok := info["router_latency_ms"].(float64); !ok || routerLatency < 0 {
			t.Errorf("expected valid router_latency_ms float64, got %v", info)
		}

		connectedPeers, ok := info["connected_peers"].(float64)
		if !ok || connectedPeers < 2 {
			t.Errorf("expected at least 2 connected peers (router + node B), got %v", info)
		}
	})

	t.Run("logs", func(t *testing.T) {
		resp := debugGet(t, actualApiAddrA, "/debug/logs")
		if !strings.Contains(resp, "Starting MCP server") && !strings.Contains(resp, "SAM Node Online") {
			t.Errorf("expected logs to contain startup messages, got: %v", resp)
		}
	})
}
