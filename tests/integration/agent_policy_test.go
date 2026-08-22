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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/google/sam/api"
)

// TestAgentPolicyCUJ is the selling point end to end: two agents behind two
// gateways on the same node, reaching the same service, told apart by mesh
// policy on the far side.
//
// The provider decides. Node A's local attenuation demands that the caller be
// named, and named within a namespace it accepts. Neither gateway can influence
// that: the agent each one asserts is the identity its bundle gave it.
func TestAgentPolicyCUJ(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	_, hubAddr := startMockRouter(t)

	homeA := t.TempDir()
	homeB := t.TempDir()
	apiToken := "test-token"

	// Only agents under prod.acme.example may reach this node's services. The
	// suffix is matched with a leading dot so a lookalike authority such as
	// "evil-prod.acme.example" cannot satisfy it.
	configA := filepath.Join(homeA, "sam-node.yaml")
	if err := os.WriteFile(configA, []byte(`version: "v1alpha1"
attenuation:
  checks:
    - 'check if agent($a), $a.ends_with(".prod.acme.example")'
`), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	sockDir, err := os.MkdirTemp("", "agentpolicy")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	nodeSocket := filepath.Join(sockDir, "node.sock")

	_ = startBackgroundNode(t, nodeBin, hubAddr, homeA,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--discovery-interval", "100ms",
		"--config", configA,
	)
	_ = startBackgroundNode(t, nodeBin, hubAddr, homeB,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--discovery-interval", "100ms",
		"--socket-path", nodeSocket,
	)

	apiAddrA := waitForMCPAddr(t, filepath.Join(homeA, "node.log"))
	apiAddrB := waitForMCPAddr(t, filepath.Join(homeB, "node.log"))
	waitForAPI(t, apiAddrA)
	waitForAPI(t, apiAddrB)

	addrA := waitForPeerInfoInLog(t, filepath.Join(homeA, "node.log"))
	callMCP(t, apiAddrB, "connect_peer", map[string]any{"peer_addr": addrA})
	waitForDHTPeers(t, apiAddrA)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"test-model"}]}`))
	}))
	defer backend.Close()

	registerInferenceService(t, apiAddrA, apiToken, "test-llm", backend.URL)

	// Not waitForFacadeModel: node A's own catalog probe carries no agent, so a
	// provider demanding one refuses it and its models never appear in a peer's
	// /v1/models listing. That is a real consequence of this policy shape, not a
	// test artefact -- see internal/node/agent.go.
	waitForDiscoverableService(t, apiAddrB, apiToken, "inference", "test-llm")

	tests := []struct {
		name       string
		agentID    string
		wantStatus int
	}{
		{
			name:       "an agent in the namespace the provider accepts",
			agentID:    "reviewer-7.prod.acme.example",
			wantStatus: http.StatusOK,
		},
		{
			name:       "an agent outside it, on the same node and the same gateway build",
			agentID:    "auditor-1.staging.acme.example",
			wantStatus: http.StatusForbidden,
		},
		{
			// A lookalike authority must not satisfy a suffix match, which is
			// the whole reason agent identifiers are dot-anchored.
			name:       "an agent whose authority merely looks similar",
			agentID:    "intruder.evil-prod.acme.example",
			wantStatus: http.StatusForbidden,
		},
		{
			// Without a bundle the gateway asserts nothing, so a provider that
			// demands an agent refuses the request rather than falling back to
			// trusting the node.
			name:       "an unidentified sandbox",
			agentID:    "",
			wantStatus: http.StatusForbidden,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			agentSocket := filepath.Join(sockDir, string(rune('a'+i))+".sock")
			startBoundaryForAgent(t, agentSocket, nodeSocket, tc.agentID)

			resp, err := boundaryClient(t, agentSocket).Get(
				"http://test-llm.inference." + api.MeshZone + "/v1/models")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %s, want %d", resp.Status, tc.wantStatus)
			}
		})
	}

	// The same policy, over the stream datapath. Tool calls authenticate with an
	// AuthFrame rather than HTTP headers, so this is a genuinely separate path
	// and used to be unattributed while inference was not.
	t.Run("tool calls carry the agent too", func(t *testing.T) {
		tools := httptest.NewServer(newBoundaryMCPHandler(t))
		defer tools.Close()
		registerService(t, apiAddrA, apiToken, "calc", tools.URL)

		peerA := extractPeerID(addrA)

		for i, tc := range []struct {
			name      string
			agentID   string
			wantAllow bool
		}{
			{name: "an agent the provider accepts", agentID: "reviewer-9.prod.acme.example", wantAllow: true},
			{name: "an agent it does not", agentID: "auditor-2.staging.acme.example"},
			{name: "an unidentified sandbox"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				agentSocket := filepath.Join(sockDir, "tool"+string(rune('a'+i))+".sock")
				startBoundaryForAgent(t, agentSocket, nodeSocket, tc.agentID)

				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()

				session := connectMCPThroughBoundary(t, ctx, boundaryClient(t, agentSocket))
				defer func() { _ = session.Close() }()

				res, err := session.CallTool(ctx, &mcp.CallToolParams{
					Name: "call_remote_tool",
					Arguments: map[string]any{
						"peer_id":   peerA,
						"tool_name": "mcp://calc/add",
						"arguments": map[string]any{},
					},
				})
				if err != nil {
					t.Fatalf("call_remote_tool: %v", err)
				}

				var got string
				for _, content := range res.Content {
					if text, ok := content.(*mcp.TextContent); ok {
						got += text.Text
					}
				}
				reached := strings.Contains(got, "fake-result:add")
				if reached != tc.wantAllow {
					t.Errorf("tool reached = %v, want %v; result was %q", reached, tc.wantAllow, got)
				}
			})
		}
	})
}

// waitForDiscoverableService polls until a peer offering the service is visible,
// which unlike a model listing needs no call the provider's policy might refuse.
func waitForDiscoverableService(t *testing.T, apiAddr, token, svcType, svcName string) {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet,
			"http://"+apiAddr+"/sam/service/discover?type="+svcType+"&name="+svcName, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set(api.HeaderSamAuthentication, "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			var providers []*api.DiscoveredProvider
			decodeErr := json.NewDecoder(resp.Body).Decode(&providers)
			_ = resp.Body.Close()
			if decodeErr == nil && len(providers) > 0 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s://%s to be discoverable", svcType, svcName)
}
