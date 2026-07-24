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
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/storage"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

func TestNodeRevocationIntegration(t *testing.T) {
	cpBin := buildBinary(t, "./cmd/sam-control-plane")
	routerBin := buildBinary(t, "./cmd/sam-router")
	nodeBin := buildBinary(t, "./cmd/sam-node")
	clientBin := buildBinary(t, "./cmd/mcp-client")

	tmpDir := t.TempDir()

	// 1. Create a mock policy file granting "router" role
	policyFile := filepath.Join(tmpDir, "policies.yaml")
	policyContent := `version: "v1alpha1"
bindings:
  - members: ["user:mock-user"]
    role: admin
roles:
  admin:
    allowed_services: ["*"]
    allowed_targets: ["*"]
`
	writePolicyWithRouter(t, policyFile, policyContent)

	// Start Mock OIDC Server
	oidcURL, mintToken := startCustomMockOIDC(t)

	cpPort := getFreePort(t)
	routerPort := getFreePort(t)

	// 2. Start Control Plane (PostgreSQL is used in GKE/Kind, but SQLite is completely fine here for in-process integration test speed)
	cpCmd := exec.Command(cpBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", cpPort),
		"--admin-token", "test-admin-token",
		"--db-dsn", filepath.Join(tmpDir, "cp-keys.db"),
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
	)
	cpCmd.Stdout = os.Stdout
	cpCmd.Stderr = os.Stderr
	if err := cpCmd.Start(); err != nil {
		t.Fatalf("failed to start control plane: %v", err)
	}
	defer func() {
		_ = cpCmd.Process.Kill()
		_ = cpCmd.Wait()
	}()

	waitForControlPlane(t, cpPort)
	injectPolicyYAML(t, cpPort, "test-admin-token", policyFile)

	// 3. Start Router
	routerJWT := mintToken(map[string]interface{}{
		"sub":    "router-integration-1",
		"groups": []string{"routers"},
		"roles":  []string{api.RoleRouter},
	})

	routerCmd := exec.Command(routerBin,
		"--control-plane", fmt.Sprintf("http://127.0.0.1:%d", cpPort),
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", routerPort),
		"--keys-path", filepath.Join(tmpDir, "router-keys.db"),
		"--allow-loopback",
		"--oidc-token", routerJWT,
		"--lease-renew-interval", "2s",
		"--keys-sync-interval", "1s",
	)
	routerCmd.Stdout = os.Stdout
	routerCmd.Stderr = os.Stderr
	if err := routerCmd.Start(); err != nil {
		t.Fatalf("failed to start router: %v", err)
	}
	defer func() {
		_ = routerCmd.Process.Kill()
		_ = routerCmd.Wait()
	}()

	fetchPeerID(t, cpPort)

	// 4. Start Node 1
	node1ApiPort := getFreePort(t)
	node1Home := filepath.Join(tmpDir, "node1_home")
	_ = os.MkdirAll(node1Home, 0755)

	logDir := filepath.Join(repoRoot(t), "tests/integration/logs")
	_ = os.MkdirAll(logDir, 0755)

	node1LogPath := filepath.Join(logDir, "node1.log")
	node1LogFile, _ := os.Create(node1LogPath)
	defer func() { _ = node1LogFile.Close() }()

	node1Cmd := exec.Command(nodeBin, "run",
		"--hub", fmt.Sprintf("http://127.0.0.1:%d", cpPort),
		"--jwt", mintToken(map[string]interface{}{"sub": "mock-user", "roles": []string{api.RoleNode}}),
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--allow-loopback",
		"--bind-addr", fmt.Sprintf("127.0.0.1:%d", node1ApiPort),
		"--api-token", "node1-token",
		"--log-level", "debug",
	)
	node1Cmd.Env = append(os.Environ(), "HOME="+node1Home, "XDG_CONFIG_HOME="+filepath.Join(node1Home, ".config"))
	node1Cmd.Stdout = node1LogFile
	node1Cmd.Stderr = node1LogFile
	if err := node1Cmd.Start(); err != nil {
		t.Fatalf("failed to start node 1: %v", err)
	}
	defer func() {
		_ = node1Cmd.Process.Kill()
		_ = node1Cmd.Wait()
	}()

	// 5. Start Node 2
	node2ApiPort := getFreePort(t)
	node2Home := filepath.Join(tmpDir, "node2_home")
	_ = os.MkdirAll(node2Home, 0755)

	node2LogPath := filepath.Join(logDir, "node2.log")
	node2LogFile, _ := os.Create(node2LogPath)
	defer func() { _ = node2LogFile.Close() }()

	node2Cmd := exec.Command(nodeBin, "run",
		"--hub", fmt.Sprintf("http://127.0.0.1:%d", cpPort),
		"--jwt", mintToken(map[string]interface{}{"sub": "mock-user", "roles": []string{api.RoleNode}}),
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--allow-loopback",
		"--bind-addr", fmt.Sprintf("127.0.0.1:%d", node2ApiPort),
		"--api-token", "node2-token",
		"--log-level", "debug",
	)
	node2Cmd.Env = append(os.Environ(), "HOME="+node2Home, "XDG_CONFIG_HOME="+filepath.Join(node2Home, ".config"))
	node2Cmd.Stdout = node2LogFile
	node2Cmd.Stderr = node2LogFile
	if err := node2Cmd.Start(); err != nil {
		t.Fatalf("failed to start node 2: %v", err)
	}
	defer func() {
		_ = node2Cmd.Process.Kill()
		_ = node2Cmd.Wait()
	}()

	// Wait for nodes to go online actively
	waitForNodeOnline(t, node1LogPath)
	waitForNodeOnline(t, node2LogPath)

	// Extract Node 2's PeerID and Address from its log
	node2LogData, _ := os.ReadFile(node2LogPath)
	rePeerID := regexp.MustCompile(`PeerID: (12D3Koo[a-zA-Z0-9]+)`)
	matches := rePeerID.FindStringSubmatch(string(node2LogData))
	if len(matches) < 2 {
		t.Fatalf("failed to find Node 2 peer ID in logs:\n%s", string(node2LogData))
	}
	node2PeerID := matches[1]

	reAddr := regexp.MustCompile(`Listening on: \[(/ip4/127.0.0.1/tcp/\d+)`)
	matchesAddr := reAddr.FindStringSubmatch(string(node2LogData))
	if len(matchesAddr) < 2 {
		t.Fatalf("failed to find Node 2 listening TCP address in logs:\n%s", string(node2LogData))
	}
	node2TCPAddr := matchesAddr[1]

	// 6. Request Node 1 to connect to Node 2
	connectArgs := fmt.Sprintf(`{"peer_addr":"%s/p2p/%s"}`, node2TCPAddr, node2PeerID)
	stdout, stderr, err := runCommand(t, repoRoot(t), 5*time.Second, nil, "",
		clientBin,
		"-url", fmt.Sprintf("http://127.0.0.1:%d/mcp", node1ApiPort),
		"-token", "node1-token",
		"-tool", "connect_peer",
		"-args", connectArgs,
	)
	if err != nil {
		t.Fatalf("connect_peer failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// Verify Node 1 is connected to Node 2
	time.Sleep(1 * time.Second)
	stdout, stderr, err = runCommand(t, repoRoot(t), 5*time.Second, nil, "",
		clientBin,
		"-url", fmt.Sprintf("http://127.0.0.1:%d/mcp", node1ApiPort),
		"-token", "node1-token",
		"-tool", "get_mesh_info",
		"-args", "{}",
	)
	if err != nil {
		t.Fatalf("get_mesh_info failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, node2PeerID) {
		t.Fatalf("Node 1 is not connected to Node 2. peers: %s", stdout)
	}

	// 7. Ban Node 2 using CP admin CLI tool
	banCmd := exec.Command(cpBin, "admin", "ban",
		"--peer", node2PeerID,
		"--db-dsn", filepath.Join(tmpDir, "cp-keys.db"),
	)
	banCmd.Stdout = os.Stdout
	banCmd.Stderr = os.Stderr
	if err := banCmd.Run(); err != nil {
		t.Fatalf("failed to ban node via admin CLI: %v", err)
	}

	// Fetch current signing private key from DB
	store, err := storage.NewSQLStore("sqlite", filepath.Join(tmpDir, "cp-keys.db"))
	if err != nil {
		t.Fatalf("failed to open cp database: %v", err)
	}
	validKeys, err := store.GetAllValidKeys(context.Background())
	_ = store.Close()
	if err != nil {
		t.Fatalf("failed to get valid keys: %v", err)
	}
	var cpPrivKey ed25519.PrivateKey
	for _, k := range validKeys {
		if len(k.Private) == ed25519.PrivateKeySize {
			cpPrivKey = k.Private
			break
		}
	}
	if cpPrivKey == nil {
		t.Fatal("no valid CP signing private key found in DB")
	}

	// Create and sign MeshEvent_BANNED
	event := &api.MeshEvent{
		Type:      api.MeshEvent_BANNED,
		PeerId:    node2PeerID,
		Timestamp: time.Now().UnixMilli(),
	}
	eventData, err := proto.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}
	event.Signature = ed25519.Sign(cpPrivKey, eventData)

	// Extract Node 1's PeerID and Address from its log
	node1LogData, _ := os.ReadFile(node1LogPath)
	matches1 := rePeerID.FindStringSubmatch(string(node1LogData))
	if len(matches1) < 2 {
		t.Fatalf("failed to find Node 1 peer ID in logs:\n%s", string(node1LogData))
	}
	node1PeerID := matches1[1]

	matchesAddr1 := reAddr.FindStringSubmatch(string(node1LogData))
	if len(matchesAddr1) < 2 {
		t.Fatalf("failed to find Node 1 listening TCP address in logs:\n%s", string(node1LogData))
	}
	node1TCPAddr := matchesAddr1[1]

	// Publish Gossip event directly to Node 1
	node1AddrStr := fmt.Sprintf("%s/p2p/%s", node1TCPAddr, node1PeerID)
	publishGossipEvent(t, node1AddrStr, event)

	// 8. Wait for revocation event to propagate and Node 1 to disconnect Node 2 actively
	waitForNodeDisconnection(t, clientBin, node1ApiPort, node2PeerID)
}

func publishGossipEvent(t *testing.T, routerAddrStr string, event *api.MeshEvent) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("failed to create libp2p host: %v", err)
	}
	defer func() { _ = h.Close() }()

	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		t.Fatalf("failed to create gossipsub: %v", err)
	}

	topic, err := ps.Join(api.GossipEvents)
	if err != nil {
		t.Fatalf("failed to join topic: %v", err)
	}
	defer func() { _ = topic.Close() }()

	targetAddr, err := multiaddr.NewMultiaddr(routerAddrStr)
	if err != nil {
		t.Fatalf("failed to parse router addr: %v", err)
	}
	targetInfo, err := peer.AddrInfoFromP2pAddr(targetAddr)
	if err != nil {
		t.Fatalf("failed to get AddrInfo: %v", err)
	}

	if err := h.Connect(ctx, *targetInfo); err != nil {
		t.Fatalf("failed to connect to router: %v", err)
	}

	// Wait for connection to settle in mesh (wait for peer to join the topic)
	peerID := targetInfo.ID
	checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
	defer checkCancel()

	found := false
	for !found {
		select {
		case <-checkCtx.Done():
			found = true
		default:
			peers := ps.ListPeers(api.GossipEvents)
			for _, p := range peers {
				if p == peerID {
					found = true
					break
				}
			}
			if !found {
				time.Sleep(50 * time.Millisecond)
			}
		}
	}

	data, err := proto.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}

	if err := topic.Publish(ctx, data); err != nil {
		t.Fatalf("failed to publish event: %v", err)
	}
}

func waitForNodeDisconnection(t *testing.T, clientBin string, node1ApiPort int, node2PeerID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for {
		stdout, _, err := runCommand(t, repoRoot(t), 2*time.Second, nil, "",
			clientBin,
			"-url", fmt.Sprintf("http://127.0.0.1:%d/mcp", node1ApiPort),
			"-token", "node1-token",
			"-tool", "get_mesh_info",
			"-args", "{}",
		)
		if err == nil && !strings.Contains(stdout, node2PeerID) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for Node 1 to disconnect Node 2")
		case <-time.After(200 * time.Millisecond):
		}
	}
}
