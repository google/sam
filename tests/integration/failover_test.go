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

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func TestFailoverUpdatesRelay(t *testing.T) {
	hubBin := buildBinary(t, "./cmd/sam-hub")
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

	httpPortA := getFreePort(t)
	p2pPortA := getFreePort(t)
	httpPortB := getFreePort(t)
	p2pPortB := getFreePort(t)

	// Mock OIDC
	oidcURL, jwtTokenStr := startMockOIDC(t)
	jwtPath := filepath.Join(tmpDir, "jwt.txt")
	if err := os.WriteFile(jwtPath, []byte(jwtTokenStr), 0644); err != nil {
		t.Fatal(err)
	}

	// Dynamic Load Balancer for HTTP discovery
	var lbMu sync.Mutex
	activeHubPort := httpPortA

	lb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lbMu.Lock()
		targetPort := activeHubPort
		lbMu.Unlock()

		target, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", targetPort))
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ServeHTTP(w, r)
	}))
	defer lb.Close()

	// Start Hub A
	cmdA := exec.Command(hubBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", httpPortA),
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", p2pPortA),
		"--policy-file", policyFile,
		"--keys-db", filepath.Join(tmpDir, "keysA.db"),
		"--allow-loopback",
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
	)
	var stdoutA, stderrA safeBuffer
	cmdA.Stdout = &stdoutA
	cmdA.Stderr = &stderrA
	if err := cmdA.Start(); err != nil {
		t.Fatalf("failed to start Hub A: %v", err)
	}

	// Fetch Hub A's Peer ID
	peerIDA := fetchPeerID(t, httpPortA)
	t.Logf("Hub A PeerID: %s", peerIDA) // Copy keysA.db to keysB.db to avoid bbolt file lock conflicts
	keysA := filepath.Join(tmpDir, "keysA.db")
	keysB := filepath.Join(tmpDir, "keysB.db")
	data, err := os.ReadFile(keysA)
	if err != nil {
		t.Fatalf("Failed to read keysA.db: %v", err)
	}
	if err := os.WriteFile(keysB, data, 0600); err != nil {
		t.Fatalf("Failed to write keysB.db: %v", err)
	}

	// Start Hub B
	cmdB := exec.Command(hubBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", httpPortB),
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", p2pPortB),
		"--policy-file", policyFile,
		"--keys-db", keysB,
		"--allow-loopback",
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
	)
	var stdoutB, stderrB safeBuffer
	cmdB.Stdout = &stdoutB
	cmdB.Stderr = &stderrB
	if err := cmdB.Start(); err != nil {
		t.Fatalf("failed to start Hub B: %v", err)
	}
	defer func() { _ = cmdB.Process.Kill() }()

	peerIDB := fetchPeerID(t, httpPortB)
	t.Logf("Hub B PeerID: %s", peerIDB)

	// Start Node B
	nodeHome := filepath.Join(tmpDir, "node-home")
	env := append(os.Environ(),
		"HOME="+nodeHome,
		"XDG_CONFIG_HOME="+filepath.Join(nodeHome, ".config"),
	)
	cmdNode := exec.Command(nodeBin, "run",
		"--hub", lb.URL,
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
	defer func() { _ = cmdNode.Process.Kill() }()

	// Wait for Node B to get a reservation on Hub A
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
		if strings.Contains(out, "Yielding static relays to AutoRelay") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if nodePeerID == "" {
		t.Fatalf("Node B failed to get PeerID in time.\nOutput:\n%s", out)
	}
	t.Logf("Node B started. Node PeerID: %s", nodePeerID)

	// Now FAILOVER: Switch LB to Hub B and KILL Hub A
	t.Logf("Initiating failover to Hub B...")
	lbMu.Lock()
	activeHubPort = httpPortB
	lbMu.Unlock()
	_ = cmdA.Process.Kill()

	// Wait for Node B's AutoRelay to get updated
	for i := 0; i < 150; i++ {
		out = stdoutNode.String() + stderrNode.String()
		if strings.Contains(out, "Successfully reconnected to Hub via HTTP fallback.") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(out, "Successfully reconnected to Hub via HTTP fallback.") {
		t.Fatalf("Node B failed to detect failover and reconnect.\nOutput:\n%s", out)
	}
	t.Log("Node B successfully reconnected to Hub B!")

	// Final verification: Ensure we can actually reach Node B via the Hub B relay
	relayAddrStr := fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/p2p/%s/p2p-circuit/p2p/%s", p2pPortB, peerIDB, nodePeerID)
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
		clientHost.Close() // nolint:errcheck
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
