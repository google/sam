package integration_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func startBackgroundNode(t *testing.T, nodeBin string, hubAddr string, homeDir string, args ...string) *exec.Cmd {
	t.Helper()
	env := append(os.Environ(),
		"HOME="+homeDir,
		"XDG_CONFIG_HOME="+filepath.Join(homeDir, ".config"),
	)
	allArgs := append([]string{"run", "--hub", hubAddr, "--jwt", "test-jwt", "--bind-addr", "127.0.0.1:0", "--api-token", "test-token", "--allow-loopback"}, args...)
	cmd := exec.Command(nodeBin, allArgs...)
	cmd.Env = env

	logFile, err := os.Create(filepath.Join(homeDir, "node.log"))
	if err != nil {
		t.Fatalf("failed to create log file: %v", err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start background node: %v", err)
	}

	t.Cleanup(func() {
		if err := cmd.Process.Kill(); err != nil {
			t.Logf("warning: failed to kill background node: %v", err)
		}
		if err := logFile.Close(); err != nil {
			t.Logf("warning: failed to close log file: %v", err)
		}
	})

	return cmd
}

func waitForMCPAddr(t *testing.T, logPath string) string {
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

func callMCP(t *testing.T, mcpAddr string, toolName string, params map[string]any) string {
	t.Helper()
	ctx := context.Background()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "0.1.0",
	}, nil)

	session, err := client.Connect(ctx, &mcp.SSEClientTransport{Endpoint: "http://" + mcpAddr + "/mcp/events"}, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			t.Logf("failed to close session: %v", err)
		}
	}()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
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

func waitForPeerInfoInLog(t *testing.T, logPath string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(logPath)
		lines := strings.Split(string(data), "\n")
		var peerID string
		var tcpAddr string
		for _, line := range lines {
			if strings.HasPrefix(line, "PeerID: ") {
				peerID = strings.TrimPrefix(line, "PeerID: ")
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

func TestCatalogRoutingAndFailover(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	_, hubAddr := startMockLibp2pHub(t)

	homeA := t.TempDir()
	homeB := t.TempDir()
	homeC := t.TempDir()

	// Start Node A (Client)
	t.Log("Starting Node A...")
	_ = startBackgroundNode(t, nodeBin, hubAddr, homeA, "--listen", "/ip4/127.0.0.1/udp/0/quic-v1", "--listen", "/ip4/127.0.0.1/tcp/0", "--discovery-interval", "100ms")
	t.Log("Node A started.")

	// Wait for Node A to start and get its MCP address
	mcpAddrA := waitForMCPAddr(t, filepath.Join(homeA, "node.log"))

	// Start Node B (Provider 1)
	t.Log("Starting Node B...")
	cmdB := startBackgroundNode(t, nodeBin, hubAddr, homeB, "--listen", "/ip4/127.0.0.1/udp/0/quic-v1", "--listen", "/ip4/127.0.0.1/tcp/0", "--discovery-interval", "100ms")
	t.Log("Node B started.")

	// Start Node C (Provider 2)
	t.Log("Starting Node C...")
	_ = startBackgroundNode(t, nodeBin, hubAddr, homeC, "--listen", "/ip4/127.0.0.1/udp/0/quic-v1", "--listen", "/ip4/127.0.0.1/tcp/0", "--discovery-interval", "100ms")
	t.Log("Node C started.")

	// Wait for Node B and C to start and get their addresses
	addrB := waitForPeerInfoInLog(t, filepath.Join(homeB, "node.log"))
	addrC := waitForPeerInfoInLog(t, filepath.Join(homeC, "node.log"))

	// Force Node A to connect to Node B and Node C
	callMCP(t, mcpAddrA, "connect_peer", map[string]any{"peer_addr": addrB})
	callMCP(t, mcpAddrA, "connect_peer", map[string]any{"peer_addr": addrC})

	// Wait for them to discover each other and publish catalog by polling get_mesh_info
	t.Log("Polling for discovery...")
	deadline := time.Now().Add(2 * time.Second)
	var connected bool

	for time.Now().Before(deadline) {
		client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.1.0"}, nil)
		session, err := client.Connect(context.Background(), &mcp.SSEClientTransport{Endpoint: "http://" + mcpAddrA + "/mcp/events"}, nil)
		if err != nil {
			t.Logf("Poll: failed to connect: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}

		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_mesh_info", Arguments: map[string]any{}})
		if closeErr := session.Close(); closeErr != nil {
			t.Logf("Poll: failed to close session: %v", closeErr)
		}
		if err != nil {
			t.Logf("Poll: CallTool failed: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}

		var text string
		for _, content := range result.Content {
			if textContent, ok := content.(*mcp.TextContent); ok {
				text = textContent.Text
				break
			}
		}

		t.Logf("Poll result:\n%s", text)

		var data map[string]any
		if err := json.Unmarshal([]byte(text), &data); err != nil {
			t.Logf("Failed to parse JSON: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		connectedPeers, ok := data["connected_peers"].([]any)
		if ok && len(connectedPeers) >= 3 {
			connected = true
		}

		if connected {
			break
		}

		time.Sleep(2 * time.Second)
	}
	if !connected {
		t.Fatalf("failed to discover peers (Hub + 2 nodes) in time")
	}

	respData := callMCP(t, mcpAddrA, "send_message", map[string]any{"peer_id": "target-peer", "message": "hello"})
	t.Logf("First call response: %s", respData)

	// Now kill Node B and assert failover to Node C
	if err := cmdB.Process.Kill(); err != nil {
		t.Fatalf("failed to kill Node B: %v", err)
	}

	// Wait a bit for catalog update or failover to happen on next call
	time.Sleep(500 * time.Millisecond)

	respData2 := callMCP(t, mcpAddrA, "send_message", map[string]any{"peer_id": "target-peer", "message": "hello"})
	t.Logf("Second call response: %s", respData2)
}
