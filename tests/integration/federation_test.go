package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
	"google.golang.org/protobuf/proto"
)

func TestHubFederationAndRelay(t *testing.T) {
	hubBin := buildBinary(t, "./cmd/sam-hub")
	nodeBin := buildBinary(t, "./cmd/sam-node")
	clientBin := buildBinary(t, "./cmd/mcp-client")

	tmpDir := t.TempDir()

	// Create a mock policy file
	policyFile := filepath.Join(tmpDir, "policies.yaml")
	policyContent := `version: "v1alpha1"
bindings:
  - user: mock-user
    role: admin
roles:
  admin:
    mcp:
      allowed_tools: 
        - "/sam/mcp/1.0.0"
        - "list_local_services"
        - "discover_remote_services"
        - "federated-tool"
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	portA := getFreePort(t)
	portB := getFreePort(t)
	p2pPortA := getFreePort(t)
	p2pPortB := getFreePort(t)

	// Start Fake DNS Server
	dnsServer, err := NewFakeDNSServer(map[string]string{
		"test-hub.local": "127.0.0.1",
	}, map[string][]string{})
	if err != nil {
		t.Fatalf("failed to start fake dns: %v", err)
	}
	t.Cleanup(func() { dnsServer.Hijack(t) })

	// Start Hub A
	// Mock OIDC
	oidcURL, jwtTokenStr := startMockOIDC(t)

	cmdA := exec.Command(hubBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", portA),
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", p2pPortA),
		"--policy-file", policyFile,
		"--keys-db", filepath.Join(tmpDir, "keysA.db"),
		"--allow-loopback",
		"--external-multiaddr", "/dnsaddr/test-hub.local",
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
		"--key", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	)
	cmdA.Env = append(os.Environ(), "SAM_TEST_DNS_SERVER="+dnsServer.conn.LocalAddr().String())
	var stdoutA, stderrA safeBuffer
	cmdA.Stdout = &stdoutA
	cmdA.Stderr = &stderrA

	if err := cmdA.Start(); err != nil {
		t.Fatalf("failed to start Hub A: %v", err)
	}
	defer func() { _ = cmdA.Process.Kill() }()

	// Fetch Hub A's Peer ID (which actively loops and waits for readiness)
	peerIDA := fetchPeerID(t, portA)

	// Update Fake DNS with Hub A's TXT record
	dnsServer.UpdateTXT("_dnsaddr.test-hub.local", []string{
		fmt.Sprintf("dnsaddr=/ip4/127.0.0.1/tcp/%d/p2p/%s", p2pPortA, peerIDA),
	})

	// Start Hub B, explicitly federating with Hub A via DNS
	cmdB := exec.Command(hubBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", portB),
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", p2pPortB),
		"--policy-file", policyFile,
		"--keys-db", filepath.Join(tmpDir, "keysB.db"),
		"--allow-loopback",
		"--external-multiaddr", "/dnsaddr/test-hub.local",
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
		"--key", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	)
	cmdB.Env = append(os.Environ(), "SAM_TEST_DNS_SERVER="+dnsServer.conn.LocalAddr().String())
	var stdoutB, stderrB safeBuffer
	cmdB.Stdout = io.MultiWriter(os.Stdout, &stdoutB)
	cmdB.Stderr = io.MultiWriter(os.Stderr, &stderrB)

	if err := cmdB.Start(); err != nil {
		t.Fatalf("failed to start Hub B: %v", err)
	}
	defer func() { _ = cmdB.Process.Kill() }()

	time.Sleep(2 * time.Second)

	// Node A connects to Hub A
	apiPortA := getFreePort(t)
	nodeACmd := exec.Command(nodeBin, "run",
		"--hub", fmt.Sprintf("http://127.0.0.1:%d", portA),
		"--data-dir", filepath.Join(tmpDir, "nodeA"),
		"--bind-addr", fmt.Sprintf("127.0.0.1:%d", apiPortA),
		"--api-token", "tokenA",
		"--jwt", jwtTokenStr,
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--discovery-interval", "100ms",
		"--enable-relay=true",
		"--allow-loopback=true",
	)
	var nodeStdoutA, nodeStderrA safeBuffer
	nodeACmd.Stdout = io.MultiWriter(os.Stdout, &nodeStdoutA)
	nodeACmd.Stderr = io.MultiWriter(os.Stderr, &nodeStderrA)
	if err := nodeACmd.Start(); err != nil {
		t.Fatalf("failed to start Node A: %v", err)
	}
	defer func() { _ = nodeACmd.Process.Kill() }()

	// Node B connects to Hub B
	apiPortB := getFreePort(t)
	nodeBCmd := exec.Command(nodeBin, "run",
		"--hub", fmt.Sprintf("http://127.0.0.1:%d", portB),
		"--data-dir", filepath.Join(tmpDir, "nodeB"),
		"--bind-addr", fmt.Sprintf("127.0.0.1:%d", apiPortB),
		"--api-token", "tokenB",
		"--jwt", jwtTokenStr,
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--discovery-interval", "100ms",
		"--allow-loopback=true",
	)
	var nodeStdoutB, nodeStderrB safeBuffer
	nodeBCmd.Stdout = io.MultiWriter(os.Stdout, &nodeStdoutB)
	nodeBCmd.Stderr = io.MultiWriter(os.Stderr, &nodeStderrB)
	if err := nodeBCmd.Start(); err != nil {
		t.Fatalf("failed to start Node B: %v", err)
	}
	defer func() { _ = nodeBCmd.Process.Kill() }()

	// Give nodes time to connect and sync
	waitForDHTReady(t, clientBin, apiPortA, "tokenA")
	waitForDHTReady(t, clientBin, apiPortB, "tokenB")

	// Start Mock Backend on Node A
	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc": "2.0", "id": 1, "result": {"success": true}}`))
	}))
	t.Cleanup(func() { mcpServer.Close() })

	// Publish a service on Node A
	t.Log("Publishing tool on Node A...")
	registerService(t, fmt.Sprintf("127.0.0.1:%d", apiPortA), "tokenA", "federated-tool", mcpServer.URL)
	time.Sleep(2 * time.Second)

	// Search for the service from Node B
	t.Log("Searching for tool from Node B...")
	searchCmd := exec.Command(clientBin,
		"-url", fmt.Sprintf("http://127.0.0.1:%d/mcp/events", apiPortB),
		"-token", "tokenB",
		"-tool", "discover_remote_services",
		"-args", `{"type": "mcp"}`,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var found bool
	for {
		select {
		case <-ctx.Done():
			t.Logf("Node A Stdout: %s", nodeStdoutA.String())
			t.Logf("Node A Stderr: %s", nodeStderrA.String())
			t.Logf("Node B Stdout: %s", nodeStdoutB.String())
			t.Logf("Node B Stderr: %s", nodeStderrB.String())
			t.Fatalf("timed out waiting to discover tool from Node B. Hub A logs: %s, Hub B logs: %s", stderrA.String(), stderrB.String())
		default:
			out, err := searchCmd.Output()
			if err == nil {
				// For simplicity, just check if the output contains the name
				if strings.Contains(string(out), "federated-tool") {
					found = true
					break
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
		if found {
			break
		}
	}

	t.Log("Successfully discovered federated tool via relay!")

	// Assert datapath works via Node B's local Egress Proxy
	t.Log("Testing datapath from Node B to Node A...")

	// Extract Node A's Peer ID from its logs
	peerIDRe := regexp.MustCompile(`(?m)^PeerID:\s+([A-Za-z0-9]+)$`)
	matches := peerIDRe.FindStringSubmatch(nodeStdoutA.String())
	if len(matches) < 2 {
		t.Fatalf("could not extract Node A Peer ID from logs")
	}
	peerIDA_node := matches[1]

	// The proxy path on Node B is /sam/<peerID>/mcp/federated-tool
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d/sam/%s/mcp/federated-tool", apiPortB, peerIDA_node)
	req, _ := http.NewRequest("POST", proxyURL, bytes.NewBuffer([]byte(`{"jsonrpc": "2.0", "id": 1, "method": "test"}`)))
	req.Header.Set("Authorization", "Bearer tokenB")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Datapath failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Datapath returned status %d: %s", resp.StatusCode, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"success": true`) {
		t.Fatalf("Unexpected datapath response: %s", string(body))
	}
	t.Log("Datapath works!")
}

func fetchPeerID(t *testing.T, port int) string {
	var bodyBytes []byte
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for {
		var resp *http.Response
		resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/info", port))
		if err == nil {
			bodyBytes, err = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err == nil {
				break
			}
		}

		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for /info: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}

	var info api.HubInfoResponse
	if err := proto.Unmarshal(bodyBytes, &info); err != nil {
		t.Fatalf("failed to decode /info: %v", err)
	}

	// Hub's PeerID is derived from its first listen multiaddr's /p2p/ segment
	var peerID string
	if len(info.HubAddresses) > 0 {
		peerID = extractPeerID(info.HubAddresses[0])
	}
	if peerID == "" {
		t.Fatalf("empty peer id from /info")
	}
	return peerID
}

func extractPeerID(maddrStr string) string {
	parts := strings.Split(maddrStr, "/")
	for i, part := range parts {
		if part == "p2p" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func waitForDHTReady(t *testing.T, clientBin string, apiPort int, token string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	cmdArgs := []string{
		"-url", fmt.Sprintf("http://127.0.0.1:%d/mcp/events", apiPort),
		"-token", token,
		"-tool", "get_mesh_info",
		"-args", `{}`,
	}

	for time.Now().Before(deadline) {
		cmd := exec.Command(clientBin, cmdArgs...)
		out, err := cmd.Output()
		if err == nil {
			if strings.Contains(string(out), `"dht_size":`) && !strings.Contains(string(out), `"dht_size":0`) {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("DHT not ready on port %d", apiPort)
}
