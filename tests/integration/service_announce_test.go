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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestServiceAnnouncePropagates verifies that a signed ServiceAnnounce published
// by node A (which hosts a static MCP service) is received by node B over gossip.
func TestServiceAnnouncePropagates(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	nodeBin := buildBinary(t, "./cmd/sam-node")
	_, hubAddr := startMockLibp2pHub(t)

	// Node A home with a static MCP service declared in its node config.
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
	addrA := waitForPeerInfoInLog(t, logA)

	// Node B subscribes to the announce topic and waits for A's message.
	homeB := t.TempDir()
	startBackgroundNode(t, nodeBin, hubAddr, homeB, "--listen", "/ip4/127.0.0.1/tcp/0")
	logB := filepath.Join(homeB, "node.log")
	mcpB := waitForMCPAddr(t, logB)

	// B connects to A so they share a gossip mesh.
	callMCP(t, mcpB, "connect_peer", map[string]any{"peer_addr": addrA})
	callMCP(t, mcpB, "subscribe_topic", map[string]any{"topic": "/sam/service/announce/v1"})

	// A's first announce fires ~5s after start (initial reprovide delay). Poll up to 25s.
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		out := callMCP(t, mcpB, "poll_messages", map[string]any{"topic": "/sam/service/announce/v1"})
		// poll_messages returns "Messages on topic <name>: []" when empty.
		if !strings.HasSuffix(strings.TrimSpace(out), ": []") && strings.TrimSpace(out) != "" {
			return // received at least one announce
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatal("node B never received a service announce from node A")
}
