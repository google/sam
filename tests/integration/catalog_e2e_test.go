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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startCatalog spawns the sam-catalog binary and returns the process and log path.
func startCatalog(t *testing.T, catalogBin, nodeURL, token, homeDir string) (string, *exec.Cmd) {
	t.Helper()
	logPath := filepath.Join(homeDir, "catalog.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create catalog log: %v", err)
	}

	cmd := exec.Command(catalogBin,
		"--node-url", nodeURL,
		"--node-token", token,
		"--bind-addr", "127.0.0.1:0",
		"--rewalk-interval", "30s",
		"--sweep-interval", "60s",
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		t.Fatalf("start sam-catalog: %v", err)
	}

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = logFile.Close()
	})

	return logPath, cmd
}

// waitForCatalogAddr reads the catalog log until "catalog MCP on <addr>" appears.
func waitForCatalogAddr(t *testing.T, logPath string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(logPath)
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "catalog MCP on ") {
				parts := strings.Split(line, "catalog MCP on ")
				if len(parts) > 1 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for catalog MCP addr in %s", logPath)
	return ""
}

// TestCatalogEndToEnd verifies the full catalog flow:
// - Node A announces a static MCP service (github-tools).
// - sam-catalog ingests it via bootstrap + SSE tail.
// - query_catalog returns github-tools with node A's peer ID.
func TestCatalogEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	nodeBin := buildBinary(t, "./cmd/sam-node")
	catalogBin := buildBinary(t, "./cmd/sam-catalog")
	_, hubAddr := startMockLibp2pHub(t)

	// Node A home dir with static MCP service declared.
	homeA := t.TempDir()
	cfgDir := filepath.Join(homeA, ".config", "sam")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	nodeConfig := "version: v1\nservices:\n  - type: mcp\n    name: github-tools\n    description: test\n    target_url: http://127.0.0.1:65535\n"
	cfgPath := filepath.Join(cfgDir, "node.yaml")
	if err := os.WriteFile(cfgPath, []byte(nodeConfig), 0o644); err != nil {
		t.Fatal(err)
	}

	startBackgroundNode(t, nodeBin, hubAddr, homeA,
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--config", cfgPath,
	)
	logA := filepath.Join(homeA, "node.log")

	// Resolve actual sidecar address (used by both MCP and sidecar API).
	nodeAAddr := waitForMCPAddr(t, logA)
	nodeURL := "http://" + nodeAAddr

	// Wait for sidecar API to be ready.
	waitForAPI(t, nodeAAddr)

	// Capture node A's peer ID for assertion.
	peerInfoA := waitForPeerInfoInLog(t, logA)
	// peerInfoA is "<multiaddr>/p2p/<peerID>"; extract the peer ID.
	peerIDP2P := peerInfoA[strings.LastIndex(peerInfoA, "/p2p/")+len("/p2p/"):]

	// Start sam-catalog pointed at node A.
	homeCat := t.TempDir()
	catLogPath, _ := startCatalog(t, catalogBin, nodeURL, "test-token", homeCat)
	catalogAddr := waitForCatalogAddr(t, catLogPath)

	// Poll query_catalog until github-tools appears (deadline ~30s).
	// Node A fires its first announce ~5s after start.
	type catalogEntry struct {
		Name   string `json:"Name"`
		PeerID string `json:"PeerID"`
	}

	deadline := time.Now().Add(35 * time.Second)
	var found bool
	var lastResult string
	for time.Now().Before(deadline) {
		out := callMCP(t, catalogAddr, "query_catalog", map[string]any{"type": "mcp"})
		lastResult = out
		if strings.Contains(out, "github-tools") {
			found = true
			break
		}
		time.Sleep(1 * time.Second)
	}

	if !found {
		t.Fatalf("query_catalog never returned github-tools within deadline; last result: %s", lastResult)
	}

	// Assert the entry's PeerID matches node A.
	var entries []catalogEntry
	if err := json.Unmarshal([]byte(lastResult), &entries); err != nil {
		t.Fatalf("failed to parse catalog entries: %v (raw: %s)", err, lastResult)
	}
	var matched bool
	for _, e := range entries {
		if e.Name == "github-tools" && e.PeerID == peerIDP2P {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("github-tools found but PeerID mismatch: want %s, entries: %s", peerIDP2P, lastResult)
	}
}
