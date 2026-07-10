package integration_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalPolicyCanGrantPermissions(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	tmpDir := t.TempDir()

	oidcURL, mintToken := startCustomMockOIDC(t)

	// Hub Policy that grants NOTHING.
	hubPolicyFile := filepath.Join(tmpDir, "policies.yaml")
	hubPolicyYAML := `version: "v1alpha1"
roles:
  none:
    allowed_services: []
    allowed_targets: []
bindings:
  - role: none
    members: ["user:unprivileged-user"]
  - role: none
    members: ["user:nodeB-user"]
`
	if err := os.WriteFile(hubPolicyFile, []byte(hubPolicyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	httpPortHub, cleanupHub := startControlPlaneAndRouter(t, tmpDir, oidcURL, mintToken, hubPolicyFile)
	defer cleanupHub()

	// Node B Config with a permissive local policy
	nodeBPolicyFile := filepath.Join(tmpDir, "nodeB_config.yaml")
	nodeBPolicyYAML := `version: "v1alpha1"
services:
  - type: "mcp"
    name: "test-tool"
    command: ["echo", "test-tool"]
attenuation:
  policies:
    - 'allow if true;'
`
	if err := os.WriteFile(nodeBPolicyFile, []byte(nodeBPolicyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	homeB := filepath.Join(tmpDir, "nodeB")
	apiTokenB := "tokenB"
	apiPortB := getFreePort(t)

	cmdB := exec.Command(nodeBin, "run",
		"--hub", fmt.Sprintf("http://127.0.0.1:%d", httpPortHub),
		"--data-dir", homeB,
		"--bind-addr", fmt.Sprintf("127.0.0.1:%d", apiPortB),
		"--api-token", apiTokenB,
		"--jwt", mintToken(map[string]interface{}{
			"sub": "nodeB-user",
		}),
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--allow-loopback",
		"--config", nodeBPolicyFile,
	)
	if err := os.MkdirAll(homeB, 0755); err != nil {
		t.Fatal(err)
	}
	logFileB, err := os.Create(filepath.Join(homeB, "node.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logFileB.Close() }()
	cmdB.Stdout = logFileB
	cmdB.Stderr = logFileB
	if err := cmdB.Start(); err != nil {
		t.Fatalf("Failed to start Node B: %v", err)
	}
	defer func() { _ = cmdB.Process.Kill(); _ = cmdB.Wait() }()

	actualApiAddrB := waitForMCPAddr(t, filepath.Join(homeB, "node.log"))
	waitForAPI(t, actualApiAddrB)
	addrB := waitForPeerInfoInLog(t, filepath.Join(homeB, "node.log"))

	parts := strings.Split(addrB, "/p2p/")
	if len(parts) != 2 {
		t.Fatalf("unexpected addrB format: %s", addrB)
	}
	peerIDB := parts[1]

	// Node A Config (unprivileged user)
	homeA := filepath.Join(tmpDir, "nodeA")
	apiTokenA := "tokenA"
	apiPortA := getFreePort(t)

	cmdA := exec.Command(nodeBin, "run",
		"--hub", fmt.Sprintf("http://127.0.0.1:%d", httpPortHub),
		"--data-dir", homeA,
		"--bind-addr", fmt.Sprintf("127.0.0.1:%d", apiPortA),
		"--api-token", apiTokenA,
		"--jwt", mintToken(map[string]interface{}{
			"sub": "unprivileged-user",
		}),
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--allow-loopback",
	)
	if err := os.MkdirAll(homeA, 0755); err != nil {
		t.Fatal(err)
	}
	logFileA, err := os.Create(filepath.Join(homeA, "node.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logFileA.Close() }()
	cmdA.Stdout = logFileA
	cmdA.Stderr = logFileA
	if err := cmdA.Start(); err != nil {
		t.Fatalf("Failed to start Node A: %v", err)
	}
	defer func() { _ = cmdA.Process.Kill(); _ = cmdA.Wait() }()

	actualApiAddrA := waitForMCPAddr(t, filepath.Join(homeA, "node.log"))
	waitForAPI(t, actualApiAddrA)

	// Make request from Node A to Node B
	// Even though Node A has no Hub permissions, Node B's local policy "allow if true;" should permit it.
	resp, callErr := callMCPAllowError(t, actualApiAddrA, apiTokenA, "call_remote_tool", map[string]any{
		"peer_id":   peerIDB,
		"tool_name": "mcp://test-tool/test_tool",
		"arguments": map[string]any{},
	})

	failed := false
	if callErr != nil {
		if strings.Contains(callErr.Error(), "EOF") {
			failed = false
		} else {
			failed = true
		}
	} else if strings.Contains(resp, "Authorization failed") || strings.Contains(resp, "failed to connect") || strings.Contains(resp, "token lacks") || strings.Contains(resp, "denied") {
		failed = true
	}

	if failed {
		t.Errorf("expected success due to local permissive policy, got error: %v / %s", callErr, resp)
	}
}

func TestLocalPolicyCannotBypassHubTargetConstraint(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	tmpDir := t.TempDir()

	oidcURL, mintToken := startCustomMockOIDC(t)

	// Hub Policy that grants service access but RESTRICTS target to "group:admin-only".
	hubPolicyFile := filepath.Join(tmpDir, "policies.yaml")
	hubPolicyYAML := `version: "v1alpha1"
roles:
  restricted-role:
    allowed_services: ["*"]
    allowed_targets: ["group:admin-only"]
bindings:
  - role: restricted-role
    members: ["user:client-user"]
  - role: restricted-role
    members: ["user:nodeB-user"]
`
	if err := os.WriteFile(hubPolicyFile, []byte(hubPolicyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	httpPortHub, cleanupHub := startControlPlaneAndRouter(t, tmpDir, oidcURL, mintToken, hubPolicyFile)
	defer cleanupHub()

	// Node B Config with a permissive local policy ("allow if true;")
	// Node B will NOT claim "group:admin-only", so it will fail the Hub's target check.
	nodeBPolicyFile := filepath.Join(tmpDir, "nodeB_config.yaml")
	nodeBPolicyYAML := `version: "v1alpha1"
services:
  - type: "mcp"
    name: "test-tool"
    command: ["echo", "test-tool"]
attenuation:
  policies:
    - 'allow if true;'
`
	if err := os.WriteFile(nodeBPolicyFile, []byte(nodeBPolicyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	homeB := filepath.Join(tmpDir, "nodeB")
	apiTokenB := "tokenB"
	apiPortB := getFreePort(t)

	cmdB := exec.Command(nodeBin, "run",
		"--hub", fmt.Sprintf("http://127.0.0.1:%d", httpPortHub),
		"--data-dir", homeB,
		"--bind-addr", fmt.Sprintf("127.0.0.1:%d", apiPortB),
		"--api-token", apiTokenB,
		"--jwt", mintToken(map[string]interface{}{
			"sub": "nodeB-user",
		}),
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--allow-loopback",
		"--config", nodeBPolicyFile,
	)
	if err := os.MkdirAll(homeB, 0755); err != nil {
		t.Fatal(err)
	}
	logFileB, err := os.Create(filepath.Join(homeB, "node.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logFileB.Close() }()
	cmdB.Stdout = logFileB
	cmdB.Stderr = logFileB
	if err := cmdB.Start(); err != nil {
		t.Fatalf("Failed to start Node B: %v", err)
	}
	defer func() { _ = cmdB.Process.Kill(); _ = cmdB.Wait() }()

	actualApiAddrB := waitForMCPAddr(t, filepath.Join(homeB, "node.log"))
	waitForAPI(t, actualApiAddrB)
	addrB := waitForPeerInfoInLog(t, filepath.Join(homeB, "node.log"))

	parts := strings.Split(addrB, "/p2p/")
	if len(parts) != 2 {
		t.Fatalf("unexpected addrB format: %s", addrB)
	}
	peerIDB := parts[1]

	// Node A Config (Client)
	homeA := filepath.Join(tmpDir, "nodeA")
	apiTokenA := "tokenA"
	apiPortA := getFreePort(t)

	cmdA := exec.Command(nodeBin, "run",
		"--hub", fmt.Sprintf("http://127.0.0.1:%d", httpPortHub),
		"--data-dir", homeA,
		"--bind-addr", fmt.Sprintf("127.0.0.1:%d", apiPortA),
		"--api-token", apiTokenA,
		"--jwt", mintToken(map[string]interface{}{
			"sub": "client-user",
		}),
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--allow-loopback",
	)
	if err := os.MkdirAll(homeA, 0755); err != nil {
		t.Fatal(err)
	}
	logFileA, err := os.Create(filepath.Join(homeA, "node.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logFileA.Close() }()
	cmdA.Stdout = logFileA
	cmdA.Stderr = logFileA
	if err := cmdA.Start(); err != nil {
		t.Fatalf("Failed to start Node A: %v", err)
	}
	defer func() { _ = cmdA.Process.Kill(); _ = cmdA.Wait() }()

	actualApiAddrA := waitForMCPAddr(t, filepath.Join(homeA, "node.log"))
	waitForAPI(t, actualApiAddrA)

	// Node A attempts to call Node B.
	// Node A's token allows calling "*" but restricts the target to "group:admin-only".
	// Node B doesn't have the "group:admin-only" identity, so the target check will fail.
	// Node B's local policy "allow if true;" cannot bypass this failed check.
	resp, callErr := callMCPAllowError(t, actualApiAddrA, apiTokenA, "call_remote_tool", map[string]any{
		"peer_id":   peerIDB,
		"tool_name": "mcp://test-tool/test_tool",
		"arguments": map[string]any{},
	})

	failed := false
	if callErr != nil {
		if strings.Contains(callErr.Error(), "EOF") {
			failed = false
		} else {
			failed = true
		}
	} else if strings.Contains(resp, "Authorization failed") || strings.Contains(resp, "failed to connect") || strings.Contains(resp, "token lacks") || strings.Contains(resp, "denied") || strings.Contains(resp, "biscuit") {
		failed = true
	}

	if !failed {
		t.Errorf("expected failure due to Hub target constraint check, got success. Resp: %s", resp)
	}
}
