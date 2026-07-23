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
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestHubFederationAndRelay(t *testing.T) {
	cpBin := buildBinary(t, "./cmd/sam-control-plane")
	routerBin := buildBinary(t, "./cmd/sam-router")
	nodeBin := buildBinary(t, "./cmd/sam-node")
	clientBin := buildBinary(t, "./cmd/mcp-client")

	tmpDir := t.TempDir()

	// Create a mock policy file
	policyFile := filepath.Join(tmpDir, "policies.yaml")
	policyContent := `version: "v1alpha1"
bindings:
  - members: ["user:mock-user"]
    role: admin
roles:
  admin:
    allowed_services: 
      - "mcp://*"
      - "system://sam.catalog"
    allowed_targets: ["*"]
`
	writePolicyWithRouter(t, policyFile, policyContent)

	cpPort := getFreePort(t)
	routerPortA := getFreePort(t)
	routerPortB := getFreePort(t)

	// Start Fake DNS Server
	dnsServer, err := NewFakeDNSServer(map[string]string{
		"test-hub.local": "127.0.0.1",
	}, map[string][]string{})
	if err != nil {
		t.Fatalf("failed to start fake dns: %v", err)
	}
	t.Cleanup(func() { dnsServer.Hijack(t) })

	// 1. Pre-generate keys and Peer IDs for Router A and Router B
	privA, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	privAData, err := crypto.MarshalPrivateKey(privA)
	if err != nil {
		t.Fatal(err)
	}
	peerIDA, err := peer.IDFromPrivateKey(privA)
	if err != nil {
		t.Fatal(err)
	}
	routerKeysPathA := filepath.Join(tmpDir, "router_keysA.db")
	if err := os.WriteFile(routerKeysPathA, privAData, 0600); err != nil {
		t.Fatal(err)
	}

	privB, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	privBData, err := crypto.MarshalPrivateKey(privB)
	if err != nil {
		t.Fatal(err)
	}
	peerIDB, err := peer.IDFromPrivateKey(privB)
	if err != nil {
		t.Fatal(err)
	}
	routerKeysPathB := filepath.Join(tmpDir, "router_keysB.db")
	if err := os.WriteFile(routerKeysPathB, privBData, 0600); err != nil {
		t.Fatal(err)
	}

	// Mock OIDC
	oidcURL, mintToken := startCustomMockOIDC(t)

	routerJWT := mintToken(map[string]interface{}{
		"sub":    "router-integration-1",
		"groups": []string{"routers"},
		"roles":  []string{api.RoleRouter},
	})

	// Start Control Plane. We use journal_mode(DELETE) and busy_timeout(5000)
	// to ensure concurrent node enrollment writes do not trigger SQLITE_BUSY locking failures.
	cmdCP := exec.Command(cpBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", cpPort),
		"--admin-token", "test-admin-token",
		"--db-dsn", filepath.Join(tmpDir, "cp-keys.db")+"?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)",
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
	)
	cmdCP.Stdout = os.Stdout
	cmdCP.Stderr = os.Stderr
	if err := cmdCP.Start(); err != nil {
		t.Fatalf("failed to start CP: %v", err)
	}
	defer func() { _ = cmdCP.Process.Kill(); _ = cmdCP.Wait() }()

	waitForControlPlane(t, cpPort)
	injectPolicyYAML(t, cpPort, "test-admin-token", policyFile)

	// Start Router A
	cmdRouterA := exec.Command(routerBin,
		"--control-plane", fmt.Sprintf("http://127.0.0.1:%d", cpPort),
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", routerPortA),
		"--keys-path", routerKeysPathA,
		"--allow-loopback",
		"--external-addr", "/dnsaddr/test-hub.local",
		"--oidc-token", routerJWT,
	)
	var stdoutRouterA, stderrRouterA safeBuffer
	cmdRouterA.Stdout = &stdoutRouterA
	cmdRouterA.Stderr = &stderrRouterA
	cmdRouterA.Env = append(os.Environ(), "SAM_TEST_DNS_SERVER="+dnsServer.conn.LocalAddr().String())
	if err := cmdRouterA.Start(); err != nil {
		t.Fatalf("failed to start Router A: %v", err)
	}
	defer func() { _ = cmdRouterA.Process.Kill(); _ = cmdRouterA.Wait() }()

	// Start Router B
	cmdRouterB := exec.Command(routerBin,
		"--control-plane", fmt.Sprintf("http://127.0.0.1:%d", cpPort),
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", routerPortB),
		"--keys-path", routerKeysPathB,
		"--allow-loopback",
		"--external-addr", "/dnsaddr/test-hub.local",
		"--oidc-token", routerJWT,
	)
	var stdoutRouterB, stderrRouterB safeBuffer
	cmdRouterB.Stdout = &stdoutRouterB
	cmdRouterB.Stderr = &stderrRouterB
	cmdRouterB.Env = append(os.Environ(), "SAM_TEST_DNS_SERVER="+dnsServer.conn.LocalAddr().String())
	if err := cmdRouterB.Start(); err != nil {
		t.Fatalf("failed to start Router B: %v", err)
	}
	defer func() { _ = cmdRouterB.Process.Kill(); _ = cmdRouterB.Wait() }()

	// Wait for routers to lease
	time.Sleep(3 * time.Second)

	// Verify both routers registered on the control plane
	peerInfoList := fetchActiveRouters(t, cpPort)
	if len(peerInfoList) != 2 {
		t.Fatalf("expected 2 active routers registered on control plane, got %d\nRouter A Stderr:\n%s\nRouter B Stderr:\n%s",
			len(peerInfoList), stderrRouterA.String(), stderrRouterB.String())
	}

	// Update Fake DNS with Router A and Router B multiaddresses
	dnsServer.UpdateTXT("_dnsaddr.test-hub.local", []string{
		fmt.Sprintf("dnsaddr=/ip4/127.0.0.1/tcp/%d/p2p/%s", routerPortA, peerIDA),
		fmt.Sprintf("dnsaddr=/ip4/127.0.0.1/tcp/%d/p2p/%s", routerPortB, peerIDB),
	})

	// Trigger connection sync manually to form the federation link between Router A and Router B
	time.Sleep(2 * time.Second)

	nodeJWT := mintToken(map[string]interface{}{
		"sub":   "mock-user",
		"roles": []string{api.RoleNode},
	})

	// Node A connects to Router A (via shared CP)
	apiPortA := getFreePort(t)
	nodeACmd := exec.Command(nodeBin, "run", "--hub", fmt.Sprintf("http://127.0.0.1:%d", cpPort),
		"--data-dir", filepath.Join(tmpDir, "nodeA"),
		"--bind-addr", fmt.Sprintf("127.0.0.1:%d", apiPortA),
		"--api-token", "tokenA",
		"--jwt", nodeJWT,
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--discovery-interval", "100ms",
		"--enable-relay=true",
		"--allow-loopback=true",
	)
	nodeACmd.Env = append(os.Environ(), "SAM_TEST_DNS_SERVER="+dnsServer.conn.LocalAddr().String())
	var nodeStdoutA, nodeStderrA safeBuffer
	nodeACmd.Stdout = io.MultiWriter(os.Stdout, &nodeStdoutA)
	nodeACmd.Stderr = io.MultiWriter(os.Stderr, &nodeStderrA)
	if err := nodeACmd.Start(); err != nil {
		t.Fatalf("failed to start Node A: %v", err)
	}
	defer func() { _ = nodeACmd.Process.Kill(); _ = nodeACmd.Wait() }()

	// Node B connects to Router B (via shared CP)
	apiPortB := getFreePort(t)
	nodeBCmd := exec.Command(nodeBin, "run", "--hub", fmt.Sprintf("http://127.0.0.1:%d", cpPort),
		"--data-dir", filepath.Join(tmpDir, "nodeB"),
		"--bind-addr", fmt.Sprintf("127.0.0.1:%d", apiPortB),
		"--api-token", "tokenB",
		"--jwt", nodeJWT,
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--discovery-interval", "100ms",
		"--allow-loopback=true",
	)
	nodeBCmd.Env = append(os.Environ(), "SAM_TEST_DNS_SERVER="+dnsServer.conn.LocalAddr().String())
	var nodeStdoutB, nodeStderrB safeBuffer
	nodeBCmd.Stdout = io.MultiWriter(os.Stdout, &nodeStdoutB)
	nodeBCmd.Stderr = io.MultiWriter(os.Stderr, &nodeStderrB)
	if err := nodeBCmd.Start(); err != nil {
		t.Fatalf("failed to start Node B: %v", err)
	}
	defer func() { _ = nodeBCmd.Process.Kill(); _ = nodeBCmd.Wait() }()

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
		"-url", fmt.Sprintf("http://127.0.0.1:%d/mcp", apiPortB),
		"-token", "tokenB",
		"-tool", "discover_remote_services",
		"-args", `{"type": "mcp"}`,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var found bool
	for {
		select {
		case <-ctx.Done():
			t.Logf("Node A Stdout: %s", nodeStdoutA.String())
			t.Logf("Node A Stderr: %s", nodeStderrA.String())
			t.Logf("Node B Stdout: %s", nodeStdoutB.String())
			t.Logf("Node B Stderr: %s", nodeStderrB.String())
			t.Fatalf("timed out waiting to discover tool from Node B.")
		default:
			out, err := searchCmd.Output()
			if err == nil {
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
