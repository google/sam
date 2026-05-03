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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestPubSubTools(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	_, hubAddr := startMockLibp2pHub(t)
	tmpHome1, err := os.MkdirTemp("", "pubsub-test-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Node 1 logs at: %s/node1.log", tmpHome1)

	tmpHome2, err := os.MkdirTemp("", "pubsub-test-2")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Node 2 logs at: %s/node2.log", tmpHome2)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start Node 1
	env1 := append(os.Environ(), "HOME="+tmpHome1, "XDG_CONFIG_HOME="+filepath.Join(tmpHome1, ".config"))
	cmd1 := exec.CommandContext(ctx, nodeBin, "run", "--hub", hubAddr, "--bind-addr", "127.0.0.1:0", "--listen", "/ip4/127.0.0.1/udp/5003/quic-v1", "--listen", "/ip4/127.0.0.1/tcp/5004", "--jwt", "dummy-token", "--log-level", "debug", "--discovery-interval", "100ms", "--api-token", "dummy-token")
	cmd1.Env = env1
	logFile1, err := os.Create(filepath.Join(tmpHome1, "node1.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd1.Stdout = logFile1
	cmd1.Stderr = logFile1
	if err := cmd1.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd1.Process.Kill(); _ = logFile1.Close() }()

	// Start Node 2
	env2 := append(os.Environ(), "HOME="+tmpHome2, "XDG_CONFIG_HOME="+filepath.Join(tmpHome2, ".config"))
	cmd2 := exec.CommandContext(ctx, nodeBin, "run", "--hub", hubAddr, "--bind-addr", "127.0.0.1:0", "--listen", "/ip4/127.0.0.1/udp/5005/quic-v1", "--listen", "/ip4/127.0.0.1/tcp/5006", "--jwt", "dummy-token", "--log-level", "debug", "--discovery-interval", "100ms", "--api-token", "dummy-token")
	cmd2.Env = env2
	logFile2, err := os.Create(filepath.Join(tmpHome2, "node2.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd2.Stdout = logFile2
	cmd2.Stderr = logFile2
	if err := cmd2.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd2.Process.Kill(); _ = logFile2.Close() }()

	// Helper to wait for MCP addr in log
	waitForMCPAddr := func(t *testing.T, logPath string) string {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			data, _ := os.ReadFile(logPath)
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.Contains(line, "Starting MCP server on TCP address ") {
					parts := strings.Split(line, "Starting MCP server on TCP address ")
					if len(parts) > 1 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("timeout waiting for MCP addr in log: %s", logPath)
		return ""
	}

	mcpAddr1 := waitForMCPAddr(t, filepath.Join(tmpHome1, "node1.log"))
	mcpAddr2 := waitForMCPAddr(t, filepath.Join(tmpHome2, "node2.log"))

	// Helper to call MCP tool
	callTool := func(mcpAddr string, toolName string, params map[string]any) string {
		client := mcp.NewClient(&mcp.Implementation{
			Name:    "test-client",
			Version: "0.1.0",
		}, nil)

		session, err := client.Connect(context.Background(), &mcp.SSEClientTransport{Endpoint: "http://" + mcpAddr + "/mcp/events"}, nil)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer func() {
			if err := session.Close(); err != nil {
				t.Logf("failed to close session: %v", err)
			}
		}()

		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      toolName,
			Arguments: params,
		})
		if err != nil {
			t.Fatalf("CallTool failed: %v", err)
		}

		for _, content := range result.Content {
			if textContent, ok := content.(*mcp.TextContent); ok {
				return textContent.Text
			}
		}
		return ""
	}

	waitForPeerInfoInLog := func(t *testing.T, logPath string) string {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			data, _ := os.ReadFile(logPath)
			lines := strings.Split(string(data), "\n")
			var peerID string
			var tcpAddr string
			for _, line := range lines {
				if strings.Contains(line, "PeerID: ") {
					parts := strings.Split(line, "PeerID: ")
					if len(parts) > 1 {
						peerID = strings.TrimSpace(parts[1])
					}
				}
				if strings.Contains(line, "Listening on: ") {
					parts := strings.Split(line, " ")
					for _, p := range parts {
						if strings.Contains(p, "/tcp/") {
							tcpAddr = strings.Trim(p, "[]")
						}
					}
				}
			}
			if peerID != "" && tcpAddr != "" {
				return tcpAddr + "/p2p/" + peerID
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("timeout waiting for peer info in log: %s", logPath)
		return ""
	}

	// Force Node 1 to connect to Node 2
	addr2 := waitForPeerInfoInLog(t, filepath.Join(tmpHome2, "node2.log"))
	t.Logf("Node 2 address: %s", addr2)
	callTool(mcpAddr1, "connect_peer", map[string]any{"peer_addr": addr2})
	
	// Node 1 broadcasts on topic "test-topic"
	broadcastResult := callTool(mcpAddr1, "mesh_pubsub_broadcast", map[string]any{
		"topic":   "test-topic",
		"payload": "hello from node 1",
	})
	if !strings.Contains(broadcastResult, "Published") {
		t.Fatalf("Broadcast failed: %s", broadcastResult)
	}

	// Node 2 subscribes to topic "test-topic"
	subscribeResult := callTool(mcpAddr2, "subscribe_topic", map[string]any{
		"topic": "test-topic",
	})
	if !strings.Contains(subscribeResult, "Subscribed") {
		t.Fatalf("Subscribe failed: %s", subscribeResult)
	}

	var pollResult string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		// Node 1 broadcasts on topic "test-topic" again to ensure delivery after subscription
		broadcastResult = callTool(mcpAddr1, "mesh_pubsub_broadcast", map[string]any{
			"topic":   "test-topic",
			"payload": "hello from node 1",
		})
		if !strings.Contains(broadcastResult, "Published") {
			t.Fatalf("Broadcast failed: %s", broadcastResult)
		}

		// Node 2 polls for messages on topic "test-topic"
		pollResult = callTool(mcpAddr2, "poll_messages", map[string]any{
			"topic": "test-topic",
		})
		if strings.Contains(pollResult, "hello from node 1") {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !strings.Contains(pollResult, "hello from node 1") {
		t.Fatalf("Poll failed, expected message not found: %s", pollResult)
	}
}
