package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func callMCPAllowError(t *testing.T, mcpAddr string, apiToken string, toolName string, params map[string]any) (string, error) {
	t.Helper()
	ctx := context.Background()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "0.1.0",
	}, nil)

	transport := http.DefaultTransport
	clientTransport := &mcp.StreamableClientTransport{
		Endpoint: "http://" + mcpAddr + "/mcp",
		HTTPClient: &http.Client{
			Transport: &authRoundTripper{
				token: apiToken,
				rt:    transport,
			},
		},
	}

	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		return "", fmt.Errorf("failed to connect: %v", err)
	}
	defer func() {
		_ = session.Close()
	}()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolName,
		Arguments: params,
	})
	if err != nil {
		return "", err
	}

	if res.IsError {
		var errText []string
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				errText = append(errText, tc.Text)
			}
		}
		return "", fmt.Errorf("MCP error: %s", strings.Join(errText, " "))
	}

	if len(res.Content) > 0 {
		if textContent, ok := res.Content[0].(*mcp.TextContent); ok {
			return textContent.Text, nil
		}
	}
	return "", nil
}

func TestPolicyPermutations(t *testing.T) {
	hubBin := buildBinary(t, "./cmd/sam-hub")
	nodeBin := buildBinary(t, "./cmd/sam-node")

	tmpDir := t.TempDir()

	oidcURL, mintToken := startCustomMockOIDC(t)

	// 1. Hub Policies
	hubPolicyFile := filepath.Join(tmpDir, "policies.yaml")
	hubPolicyYAML := `version: "v1alpha1"
roles:
  role-user:
    allowed_services: ["mcp:test-user"]
    allowed_targets: ["user:bob-subject"]
  role-email:
    allowed_services: ["mcp:test-email"]
    allowed_targets: ["node:nodeB"]
  role-group:
    allowed_services: ["mcp:test-group"]
    allowed_targets: ["group:compute"]
  role-node:
    allowed_services: ["mcp:test-node"]
    allowed_targets: ["group:backend"]
  role-direct:
    allowed_services: ["mcp:test-role"]
    allowed_targets: ["node:nodeB"]
  admin:
    allowed_services: ["*"]
    allowed_targets: ["*"]

bindings:
  - role: role-user
    user: "bob-subject"
  - role: role-email
    email: "bob@example.com"
  - role: role-group
    group: "eng-team"
  - role: role-node
    user: "node-user"
  - role: admin
    user: "admin-user"
  - role: admin
    user: "nodeB"
`
	if err := os.WriteFile(hubPolicyFile, []byte(hubPolicyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	httpPortHub := getFreePort(t)
	p2pPortHub := getFreePort(t)

	cmdHub := exec.Command(hubBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", httpPortHub),
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", p2pPortHub),
		"--policy-file", hubPolicyFile,
		"--keys-db", filepath.Join(tmpDir, "keys.db"),
		"--allow-loopback",
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
	)
	cmdHub.Stdout = os.Stdout
	cmdHub.Stderr = os.Stderr
	if err := cmdHub.Start(); err != nil {
		t.Fatalf("Failed to start Hub: %v", err)
	}
	defer func() { _ = cmdHub.Process.Kill() }()
	fetchPeerID(t, httpPortHub)

	// 2. Node B (Target) Config
	nodeBPolicyFile := filepath.Join(tmpDir, "nodeB_config.yaml")
	nodeBPolicyYAML := `version: "v1alpha1"
attenuation:
  rules:
    - 'target("user:bob-subject") <- true'
    - 'target("node:nodeB") <- true'
    - 'target("group:compute") <- true'
    - 'target("group:backend") <- true'

services:
  - type: "mcp"
    name: "mcp:test-user"
    command: ["echo", "test-user"]
  - type: "mcp"
    name: "mcp:test-email"
    command: ["echo", "test-email"]
  - type: "mcp"
    name: "mcp:test-group"
    command: ["echo", "test-group"]
  - type: "mcp"
    name: "mcp:test-role"
    command: ["echo", "test-role"]
  - type: "mcp"
    name: "mcp:test-node"
    command: ["echo", "test-node"]
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
		"--jwt", mintToken(map[string]interface{}{"sub": "nodeB"}),
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--trust-hub-rbac",
		"--allow-loopback",
		"--config", nodeBPolicyFile,
	)
	os.MkdirAll(homeB, 0755)
	logFileB, err := os.Create(filepath.Join(homeB, "node.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFileB.Close()
	cmdB.Stdout = logFileB
	cmdB.Stderr = logFileB
	if err := cmdB.Start(); err != nil {
		t.Fatalf("Failed to start Node B: %v", err)
	}
	defer func() { _ = cmdB.Process.Kill() }()

	actualApiAddrB := waitForMCPAddr(t, filepath.Join(homeB, "node.log"))
	waitForAPI(t, actualApiAddrB)
	addrB := waitForPeerInfoInLog(t, filepath.Join(homeB, "node.log"))

	// 3. Test Permutations
	tests := []struct {
		name         string
		jwtClaims    map[string]interface{}
		targetSvc    string
		expectAllow  bool
		expectHubErr bool
	}{
		{
			name:        "Fact sub: user(bob-subject)",
			jwtClaims:   map[string]interface{}{"sub": "bob-subject"},
			targetSvc:   "mcp:test-user",
			expectAllow: true,
		},
		{
			name:        "Fact email: email(bob@example.com)",
			jwtClaims:   map[string]interface{}{"sub": "some-id", "email": "bob@example.com"},
			targetSvc:   "mcp:test-email",
			expectAllow: true,
		},
		{
			name:        "Fact groups: group(eng-team)",
			jwtClaims:   map[string]interface{}{"sub": "some-id", "groups": []string{"eng-team"}},
			targetSvc:   "mcp:test-group",
			expectAllow: true,
		},
		{
			name:        "Fact roles: role(role-direct)",
			jwtClaims:   map[string]interface{}{"sub": "some-id", "roles": []string{"role-direct"}},
			targetSvc:   "mcp:test-role",
			expectAllow: true,
		},
		{
			name:        "Fact node: node(peerID)",
			jwtClaims:   map[string]interface{}{"sub": "node-user"},
			targetSvc:   "mcp:test-node",
			expectAllow: true,
		},
		{
			name:        "Unknown User / No Roles -> Hub Error",
			jwtClaims:   map[string]interface{}{"sub": "unknown"},
			targetSvc:   "mcp:test-user",
			expectAllow: false,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			homeA := filepath.Join(tmpDir, fmt.Sprintf("nodeA_%d", i))
			apiTokenA := "tokenA"
			apiPortA := getFreePort(t)

			jwtA := mintToken(tt.jwtClaims)

			cmdA := exec.Command(nodeBin, "run",
				"--hub", fmt.Sprintf("http://127.0.0.1:%d", httpPortHub),
				"--data-dir", homeA,
				"--bind-addr", fmt.Sprintf("127.0.0.1:%d", apiPortA),
				"--api-token", apiTokenA,
				"--jwt", jwtA,
				"--listen", "/ip4/127.0.0.1/tcp/0",
				"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
				"--trust-hub-rbac",
				"--allow-loopback",
			)
			os.MkdirAll(homeA, 0755)
			logFileA, err := os.Create(filepath.Join(homeA, "node.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer logFileA.Close()
			cmdA.Stdout = logFileA
			cmdA.Stderr = logFileA
			if err := cmdA.Start(); err != nil {
				t.Fatalf("Failed to start Node A: %v", err)
			}
			defer func() { _ = cmdA.Process.Kill() }()

			actualApiAddrA := waitForMCPAddr(t, filepath.Join(homeA, "node.log"))
			waitForAPI(t, actualApiAddrA)

			parts := strings.Split(addrB, "/p2p/")
			if len(parts) != 2 {
				t.Fatalf("unexpected addrB format: %s", addrB)
			}
			peerIDB := parts[1]

			// Use the local callMCPAllowError targeting Node A to hit Node B
			resp, callErr := callMCPAllowError(t, actualApiAddrA, apiTokenA, "call_remote_tool", map[string]any{
				"peer_id":   peerIDB,
				"tool_name": tt.targetSvc + ".test_tool",
				"arguments": map[string]any{},
			})

			// call_remote_tool might return a JSON error inside resp, or callErr might be non-nil.
			failed := false
			if callErr != nil {
				if strings.Contains(callErr.Error(), "EOF") {
					// EOF means the 'echo' backend started and exited, which means AuthZ succeeded!
					failed = false
				} else {
					failed = true
				}
			} else if strings.Contains(resp, "Authorization failed") || strings.Contains(resp, "failed to connect") || strings.Contains(resp, "token lacks") || strings.Contains(resp, "denied") {
				failed = true
			}

			if tt.expectAllow {
				if failed {
					t.Errorf("expected success, got error: %v / %s", callErr, resp)
				}
			} else {
				if !failed {
					t.Errorf("expected failure, got success: %s", resp)
				}
			}
		})
	}
}
