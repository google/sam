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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

func TestFailoverUpdatesRelay(t *testing.T) {
	cpBin := buildBinary(t, "./cmd/sam-control-plane")
	routerBin := buildBinary(t, "./cmd/sam-router")
	nodeBin := buildBinary(t, "./cmd/sam-node")

	tmpDir := t.TempDir()

	// Create a mock policy file
	policyFile := filepath.Join(tmpDir, "policies.yaml")
	policyContent := `version: "v1alpha1"
bindings: []
roles: {}
`
	writePolicyWithRouter(t, policyFile, policyContent)

	httpPortCP_A := getFreePort(t)
	routerPortA := getFreePort(t)
	httpPortCP_B := getFreePort(t)
	routerPortB := getFreePort(t)

	// Mock OIDC
	oidcURL, mintToken := startCustomMockOIDC(t)

	routerJWT := mintToken(map[string]interface{}{
		"sub":    "router-integration-1",
		"groups": []string{"routers"},
	})

	nodeJWT := mintToken(map[string]interface{}{
		"sub": "mock-user",
	})

	jwtPath := filepath.Join(tmpDir, "jwt.txt")
	if err := os.WriteFile(jwtPath, []byte(nodeJWT), 0644); err != nil {
		t.Fatal(err)
	}

	// Dynamic Load Balancer for HTTP discovery
	var lbMu sync.Mutex
	activeHubPort := httpPortCP_A

	lb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lbMu.Lock()
		targetPort := activeHubPort
		lbMu.Unlock()

		target, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", targetPort))
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ServeHTTP(w, r)
	}))
	defer lb.Close()

	dbPathA := filepath.Join(tmpDir, "cp_keysA.db")
	dbPathB := filepath.Join(tmpDir, "cp_keysB.db")
	// We override journal_mode to DELETE (disabling WAL) because WAL mode caches
	// transactions in a separate -wal file. Since this test copies dbPathA to dbPathB
	// while CP A is running, WAL mode would cause the copy to be stale/corrupt.
	// We also retain busy_timeout(5000) so that concurrent operations wait for locks
	// rather than returning SQLITE_BUSY immediately.
	dsnA := dbPathA + "?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)"
	dsnB := dbPathB + "?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)"

	// 1. Start Control Plane A temporarily to generate keyring
	cmdCP_A_temp := exec.Command(cpBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", httpPortCP_A),
		"--policy-file", policyFile,
		"--db-dsn", dsnA,
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
	)
	if err := cmdCP_A_temp.Start(); err != nil {
		t.Fatalf("failed to start temporary CP A: %v", err)
	}
	waitForControlPlane(t, httpPortCP_A)
	_ = cmdCP_A_temp.Process.Signal(os.Interrupt)
	_ = cmdCP_A_temp.Wait()

	// 2. Copy CP A keys to CP B to share the key-ring
	keysData, err := os.ReadFile(dbPathA)
	if err != nil {
		t.Fatalf("Failed to read cp_keysA.db: %v", err)
	}
	if err := os.WriteFile(dbPathB, keysData, 0600); err != nil {
		t.Fatalf("Failed to write cp_keysB.db: %v", err)
	}

	// 3. Start CP A persistently
	cmdCP_A := exec.Command(cpBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", httpPortCP_A),
		"--policy-file", policyFile,
		"--db-dsn", dsnA,
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
	)
	if err := cmdCP_A.Start(); err != nil {
		t.Fatalf("failed to start CP A: %v", err)
	}
	defer func() { _ = cmdCP_A.Process.Kill(); _ = cmdCP_A.Wait() }()

	waitForControlPlane(t, httpPortCP_A)

	// 4. Start Router A
	cmdRouterA := exec.Command(routerBin,
		"--control-plane", fmt.Sprintf("http://127.0.0.1:%d", httpPortCP_A),
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", routerPortA),
		"--keys-path", filepath.Join(tmpDir, "router_keysA.db"),
		"--allow-loopback",
		"--oidc-token", routerJWT,
	)
	if err := cmdRouterA.Start(); err != nil {
		t.Fatalf("failed to start Router A: %v", err)
	}
	defer func() { _ = cmdRouterA.Process.Kill(); _ = cmdRouterA.Wait() }()

	// Wait for Router A to renew lease and register in CP A
	time.Sleep(3 * time.Second)

	// 5. Start CP B
	cmdCP_B := exec.Command(cpBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", httpPortCP_B),
		"--policy-file", policyFile,
		"--db-dsn", dsnB,
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
	)
	if err := cmdCP_B.Start(); err != nil {
		t.Fatalf("failed to start CP B: %v", err)
	}
	defer func() { _ = cmdCP_B.Process.Kill(); _ = cmdCP_B.Wait() }()

	waitForControlPlane(t, httpPortCP_B)

	// Start Router B
	cmdRouterB := exec.Command(routerBin,
		"--control-plane", fmt.Sprintf("http://127.0.0.1:%d", httpPortCP_B),
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", routerPortB),
		"--keys-path", filepath.Join(tmpDir, "router_keysB.db"),
		"--allow-loopback",
		"--oidc-token", routerJWT,
	)
	if err := cmdRouterB.Start(); err != nil {
		t.Fatalf("failed to start Router B: %v", err)
	}
	defer func() { _ = cmdRouterB.Process.Kill(); _ = cmdRouterB.Wait() }()

	// Wait for Router B to renew lease and register in CP B
	time.Sleep(3 * time.Second)

	// Fetch Router B PeerID
	peerInfoList := fetchActiveRouters(t, httpPortCP_B)
	if len(peerInfoList) != 1 {
		t.Fatalf("expected 1 router registered on CP B, got %d", len(peerInfoList))
	}
	peerIDB := peerInfoList[0]
	t.Logf("Router B PeerID: %s", peerIDB)

	// Start Node
	nodeHome := filepath.Join(tmpDir, "node-home")
	env := append(os.Environ(),
		"HOME="+nodeHome,
		"XDG_CONFIG_HOME="+filepath.Join(nodeHome, ".config"),
	)
	cmdNode := exec.Command(nodeBin, "run", "--hub", lb.URL,
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--jwt-path", jwtPath,
		"--bind-addr", "127.0.0.1:0",
		"--api-token", "dummy-token",
		"--allow-loopback",
		"--monitor-bootstrap", "1s",
		"--monitor-interval", "1s",
		"--autorelay-min-interval", "1s",
		"--autorelay-backoff", "1s",
		"--autorelay-boot-delay", "0s",
	)
	cmdNode.Dir = repoRoot(t)
	cmdNode.Env = env
	var stdoutNode, stderrNode safeBuffer
	cmdNode.Stdout = &stdoutNode
	cmdNode.Stderr = &stderrNode

	if err := cmdNode.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmdNode.Process.Kill(); _ = cmdNode.Wait() }()

	// Wait for Node to get a reservation on Router A
	var nodePeerID string
	var out string
	for i := 0; i < 100; i++ {
		out = stdoutNode.String() + stderrNode.String()
		if strings.Contains(out, "PeerID:") {
			idx := strings.Index(out, "PeerID:")
			parts := strings.Split(strings.TrimSpace(out[idx+len("PeerID:"):]), "\n")
			if len(parts) > 0 {
				nodePeerID = strings.TrimSpace(parts[0])
			}
		}
		if nodePeerID != "" && strings.Contains(out, "Yielding static relays to AutoRelay") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if nodePeerID == "" {
		t.Fatalf("Node failed to get PeerID in time.\nOutput:\n%s", out)
	}
	t.Logf("Node started. Node PeerID: %s", nodePeerID)

	// Now FAILOVER: Switch LB to CP B and KILL CP A and Router A
	t.Logf("Initiating failover to Hub B...")
	lbMu.Lock()
	activeHubPort = httpPortCP_B
	lbMu.Unlock()
	_ = cmdCP_A.Process.Kill()
	_ = cmdRouterA.Process.Kill()

	// Wait for Node's AutoRelay to get updated
	for i := 0; i < 150; i++ {
		out = stdoutNode.String() + stderrNode.String()
		if strings.Contains(out, "Successfully reconnected to Hub via HTTP fallback") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(out, "Successfully reconnected to Hub via HTTP fallback") {
		t.Fatalf("Node failed to detect failover and reconnect.\nOutput:\n%s", out)
	}
	t.Log("Node successfully reconnected to Hub B!")

	// Final verification: Ensure we can actually reach Node B via the Router B relay
	relayAddrStr := fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/p2p/%s/p2p-circuit/p2p/%s", routerPortB, peerIDB, nodePeerID)
	relayAddr, err := multiaddr.NewMultiaddr(relayAddrStr)
	if err != nil {
		t.Fatal(err)
	}
	addrInfo, err := peer.AddrInfoFromP2pAddr(relayAddr)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var connectErr error
	for i := 0; i < 15; i++ {
		clientHost, err := libp2p.New(libp2p.NoListenAddrs, libp2p.EnableRelay())
		if err != nil {
			t.Fatal(err)
		}
		connectErr = clientHost.Connect(ctx, *addrInfo)
		_ = clientHost.Close()
		if connectErr == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}

	if connectErr != nil {
		t.Fatalf("Failed to connect to Node B via Hub B relay: %v\nOutput: %s", connectErr, stdoutNode.String()+stderrNode.String())
	}
	t.Log("Successfully connected to Node B via Hub B relay circuit!")
}

func fetchActiveRouters(t *testing.T, httpPort int) []string {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/info", httpPort))
	if err != nil {
		t.Fatalf("failed to query /info: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("query /info returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var info api.HubInfoResponse
	if err := proto.Unmarshal(body, &info); err != nil {
		t.Fatalf("failed to unmarshal HubInfoResponse: %v", err)
	}

	var peerIDs []string
	for _, addrStr := range info.HubAddresses {
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			continue
		}
		pi, err := peer.AddrInfoFromP2pAddr(ma)
		if err == nil {
			peerIDs = append(peerIDs, pi.ID.String())
		}
	}
	return peerIDs
}
