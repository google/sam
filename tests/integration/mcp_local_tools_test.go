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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPLocalTools(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")

	tmpDir := t.TempDir()

	// Create a mock policy file
	policyFile := filepath.Join(tmpDir, "policies.yaml")
	policyContent := `version: "v1alpha1"
bindings: []
roles: {}
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	oidcURL, mintToken := startCustomMockOIDC(t)
	httpPortHub, cleanupHub := startControlPlaneAndRouter(t, tmpDir, oidcURL, mintToken, policyFile)
	defer cleanupHub()

	fetchPeerID(t, httpPortHub)

	hubURL := fmt.Sprintf("http://127.0.0.1:%d", httpPortHub)
	apiToken := "test-token"

	homeA := t.TempDir()
	homeB := t.TempDir()

	nodeJWT := mintToken(map[string]interface{}{
		"sub": "mock-user",
	})

	// Start Node A
	t.Log("Starting Node A...")
	_ = startBackgroundNode(t, nodeBin, hubURL, homeA,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--bind-addr", "127.0.0.1:0",
		"--api-token", apiToken,
		"--jwt", nodeJWT,
	)

	// Start Node B
	t.Log("Starting Node B...")
	_ = startBackgroundNode(t, nodeBin, hubURL, homeB,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--bind-addr", "127.0.0.1:0",
		"--api-token", apiToken,
		"--jwt", nodeJWT,
	)

	// Resolve actual MCP address from log
	actualApiAddrA := waitForMCPAddr(t, filepath.Join(homeA, "node.log"))
	actualApiAddrB := waitForMCPAddr(t, filepath.Join(homeB, "node.log"))

	// Wait for nodes to start sidecar API
	waitForAPI(t, actualApiAddrA)
	waitForAPI(t, actualApiAddrB)

	// Resolve Peer addresses
	addrA := waitForPeerInfoInLog(t, filepath.Join(homeA, "node.log"))

	// Connect Node B to Node A directly
	callMCP(t, actualApiAddrB, "connect_peer", map[string]any{"peer_addr": addrA})

	t.Run("get_token_info", func(t *testing.T) {
		resp := callMCP(t, actualApiAddrA, "get_token_info", map[string]any{})
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

	t.Run("get_network_info", func(t *testing.T) {
		resp := callMCP(t, actualApiAddrA, "get_network_info", map[string]any{})
		var info map[string]any
		if err := json.Unmarshal([]byte(resp), &info); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}
		if addresses, ok := info["listen_addresses"].([]any); !ok || len(addresses) == 0 {
			t.Errorf("expected listen_addresses array, got %v", info)
		}
	})

	t.Run("check_connectivity", func(t *testing.T) {
		resp := callMCP(t, actualApiAddrA, "check_connectivity", map[string]any{})
		var info map[string]any
		if err := json.Unmarshal([]byte(resp), &info); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}
		if hubLatency, ok := info["hub_latency_ms"].(float64); !ok || hubLatency < 0 {
			t.Errorf("expected valid hub_latency_ms float64, got %v", info)
		}

		connectedPeers, ok := info["connected_peers"].(float64)
		if !ok || connectedPeers < 2 {
			t.Errorf("expected at least 2 connected peers (hub + node B), got %v", info)
		}
	})

	t.Run("get_recent_logs", func(t *testing.T) {
		resp := callMCP(t, actualApiAddrA, "get_recent_logs", map[string]any{})
		if !strings.Contains(resp, "Starting MCP server") && !strings.Contains(resp, "SAM Node Online") {
			t.Errorf("expected logs to contain startup messages, got: %v", resp)
		}
	})
}
