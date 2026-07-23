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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
	"google.golang.org/protobuf/proto"
)

func TestKeyRotationIntegration(t *testing.T) {
	cpBin := buildBinary(t, "./cmd/sam-control-plane")
	routerBin := buildBinary(t, "./cmd/sam-router")
	nodeBin := buildBinary(t, "./cmd/sam-node")

	tmpDir := t.TempDir()

	// 1. Create a mock policy file
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

	// 2. Start Control Plane with aggressive key rotation
	cpCmd := exec.Command(cpBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", cpPort),
		"--admin-token", "test-admin-token",
		"--db-dsn", filepath.Join(tmpDir, "cp-keys.db"),
		"--issuer", oidcURL,
		"--key-rotation-interval", "4s",
		"--key-grace-period", "2s",
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

	// 3. Start Router with aggressive key sync interval
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

	// 4. Start Node
	nodeJWT := mintToken(map[string]interface{}{
		"sub":   "mock-user",
		"roles": []string{api.RoleNode},
	})
	nodeApiPort := getFreePort(t)
	nodeHome := t.TempDir()

	nodeEnv := append(os.Environ(),
		"HOME="+nodeHome,
		"XDG_CONFIG_HOME="+filepath.Join(nodeHome, ".config"),
	)

	nodeLogPath := filepath.Join(tmpDir, "node.log")
	nodeLogFile, _ := os.Create(nodeLogPath)
	defer func() { _ = nodeLogFile.Close() }()

	nodeCmd := exec.Command(nodeBin, "run",
		"--hub", fmt.Sprintf("http://127.0.0.1:%d", cpPort),
		"--jwt", nodeJWT,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--allow-loopback",
		"--bind-addr", fmt.Sprintf("127.0.0.1:%d", nodeApiPort),
		"--api-token", "dummy-token",
		"--log-level", "debug",
	)
	nodeCmd.Env = nodeEnv
	nodeCmd.Stdout = nodeLogFile
	nodeCmd.Stderr = nodeLogFile
	if err := nodeCmd.Start(); err != nil {
		t.Fatalf("failed to start node: %v", err)
	}
	defer func() {
		_ = nodeCmd.Process.Kill()
		_ = nodeCmd.Wait()
	}()

	// Wait for Node to be online actively
	waitForNodeOnline(t, nodeLogPath)

	// Get initial keys
	initialKeys := fetchPublicKeys(t, cpPort)

	// Wait for key rotation to happen actively
	waitForKeyRotation(t, cpPort, initialKeys)

	// 6. Verify Node is still active and can communicate (it should renew successfully and remain online)
	if nodeCmd.ProcessState != nil && nodeCmd.ProcessState.Exited() {
		t.Fatalf("node process exited unexpectedly")
	}

	// Double check by looking at the node's API or verifying it doesn't crash
	clientBin := buildBinary(t, "./cmd/mcp-client")
	stdout, stderr, err := runCommand(t, repoRoot(t), 5*time.Second, nil, "",
		clientBin,
		"-url", fmt.Sprintf("http://127.0.0.1:%d/mcp", nodeApiPort),
		"-token", "dummy-token",
		"-tool", "get_mesh_info",
		"-args", "{}",
	)
	if err != nil {
		t.Fatalf("failed to query node: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "dht_size") {
		t.Fatalf("unexpected node response: %s", stdout)
	}
}

func fetchPublicKeys(t *testing.T, cpPort int) [][]byte {
	t.Helper()
	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/keys", cpPort))
	if err != nil {
		t.Fatalf("failed to get initial keys: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read keys body: %v", err)
	}
	var keysResp api.KeysResponse
	if err := proto.Unmarshal(body, &keysResp); err != nil {
		t.Fatalf("failed to unmarshal KeysResponse: %v", err)
	}
	return keysResp.PublicKeys
}

func waitForKeyRotation(t *testing.T, cpPort int, initialKeys [][]byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 1 * time.Second}
	for {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/keys", cpPort))
		if err == nil {
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err == nil {
				var keysResp api.KeysResponse
				if err := proto.Unmarshal(body, &keysResp); err == nil {
					for _, pk := range keysResp.PublicKeys {
						found := false
						for _, ik := range initialKeys {
							if bytes.Equal(pk, ik) {
								found = true
								break
							}
						}
						if !found {
							return // Found a new key!
						}
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for key rotation")
		case <-time.After(200 * time.Millisecond):
		}
	}
}
