package integration_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
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
	allArgs := append([]string{"run", "--hub", hubAddr, "--jwt", "test-jwt"}, args...)
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

func callMCP(t *testing.T, socketPath string, toolName string, params map[string]any) string {
	t.Helper()
	ctx := context.Background()
	
	oldTransport := http.DefaultClient.Transport
	defer func() { http.DefaultClient.Transport = oldTransport }()
	
	http.DefaultClient.Transport = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "0.1.0",
	}, nil)
	
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: "http://localhost/"}, nil)
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

	scratchDir := filepath.Join(repoRoot(t), "tests", "integration", "scratch")
	_ = os.RemoveAll(scratchDir) // Clear old logs
	
	homeA := filepath.Join(scratchDir, "homeA")
	homeB := filepath.Join(scratchDir, "homeB")
	homeC := filepath.Join(scratchDir, "homeC")

	if err := os.MkdirAll(homeA, 0755); err != nil {
		t.Fatalf("failed to create homeA: %v", err)
	}
	if err := os.MkdirAll(homeB, 0755); err != nil {
		t.Fatalf("failed to create homeB: %v", err)
	}
	if err := os.MkdirAll(homeC, 0755); err != nil {
		t.Fatalf("failed to create homeC: %v", err)
	}

	socketPathA := filepath.Join(homeA, ".config", "sam-mesh", "mcp.sock")

	// Start Node A (Client)
	t.Log("Starting Node A...")
	_ = startBackgroundNode(t, nodeBin, hubAddr, homeA, "--listen", "/ip4/127.0.0.1/udp/0/quic-v1", "--listen", "/ip4/127.0.0.1/tcp/0", "--discovery-interval", "100ms")
	t.Log("Node A started.")

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
	callMCP(t, socketPathA, "connect_peer", map[string]any{"peer_addr": addrB})
	callMCP(t, socketPathA, "connect_peer", map[string]any{"peer_addr": addrC})

	// Wait for them to discover each other and publish catalog by polling get_mesh_info
	t.Log("Polling for discovery...")
	deadline := time.Now().Add(2 * time.Second)
	var connected bool


	oldTransport := http.DefaultClient.Transport
	defer func() { http.DefaultClient.Transport = oldTransport }()
	
	http.DefaultClient.Transport = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPathA)
		},
	}

	for time.Now().Before(deadline) {
		client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.1.0"}, nil)
		session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: "http://localhost/"}, nil)
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

		lines := strings.Split(text, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Connected peers: ") {
				var cp int
				_, err := fmt.Sscanf(line, "Connected peers: %d", &cp)
				if err == nil && cp >= 3 {
					connected = true
					break
				}
			}
		}

		if connected {
			break
		}

		time.Sleep(2 * time.Second)
	}
	if !connected {
		t.Fatalf("failed to discover peers (Hub + 2 nodes) in time")
	}

	respData := callMCP(t, socketPathA, "send_message", map[string]any{"peer_id": "target-peer", "message": "hello"})
	t.Logf("First call response: %s", respData)

	// Now kill Node B and assert failover to Node C
	if err := cmdB.Process.Kill(); err != nil {
		t.Fatalf("failed to kill Node B: %v", err)
	}

	// Wait a bit for catalog update or failover to happen on next call
	time.Sleep(500 * time.Millisecond)

	respData2 := callMCP(t, socketPathA, "send_message", map[string]any{"peer_id": "target-peer", "message": "hello"})
	t.Logf("Second call response: %s", respData2)
}
