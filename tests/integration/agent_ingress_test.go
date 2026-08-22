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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/sambox"
)

// TestAgentIngressCUJ has an agent serve a mesh service and another node call
// it, which is the direction the boundary was not built for at first.
//
// The agent announces that it is ready and on which port. It never registers
// anything: it cannot name the URL the mesh routes to, and it cannot claim a
// name the platform did not grant it in its bundle.
func TestAgentIngressCUJ(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	_, hubAddr := startMockRouter(t)

	homeA := t.TempDir()
	homeB := t.TempDir()

	sockDir, err := os.MkdirTemp("", "ingress")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	nodeSocket := filepath.Join(sockDir, "node.sock")
	agentSocket := filepath.Join(sockDir, "agent.sock")

	_ = startBackgroundNode(t, nodeBin, hubAddr, homeA,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--discovery-interval", "100ms",
	)
	// Node B hosts the agent, and is the one that will advertise its service.
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

	addrB := waitForPeerInfoInLog(t, filepath.Join(homeB, "node.log"))
	peerB := extractPeerID(addrB)
	callMCP(t, apiAddrA, "connect_peer", map[string]any{"peer_addr": addrB})
	waitForDHTPeers(t, apiAddrB)

	// The agent's own server, inside its sandbox.
	agent := httptest.NewServer(newBoundaryMCPHandler(t))
	defer agent.Close()
	agentHost := strings.TrimPrefix(agent.URL, "http://")

	ingress := &sambox.IngressManager{
		SidecarSocket: nodeSocket,
		Allowed:       []sambox.BundleIngress{{Name: "code-reviewer", Type: "mcp"}},
		AgentAddr:     func(int) string { return agentHost },
	}
	t.Cleanup(func() { ingress.Close(context.Background()) })

	startBoundaryServing(t, agentSocket, nodeSocket, "reviewer-7.prod.acme.example", ingress)
	client := boundaryClient(t, agentSocket)

	t.Run("a name the platform did not grant is refused", func(t *testing.T) {
		resp, err := client.Post("http://"+api.MeshEntrypointHost+"/ingress",
			"application/json", strings.NewReader(`{"name":"payments","type":"mcp","port":9000}`))
		if err != nil {
			t.Fatalf("Post: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %s, want 403", resp.Status)
		}
	})

	t.Run("the agent announces and the mesh can reach it", func(t *testing.T) {
		resp, err := client.Post("http://"+api.MeshEntrypointHost+"/ingress",
			"application/json", strings.NewReader(`{"name":"code-reviewer","type":"mcp","port":8080}`))
		if err != nil {
			t.Fatalf("Post: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %s, want 204", resp.Status)
		}

		// Node A calls the agent's tool across the mesh, knowing only the
		// service name the agent published.
		got := callMCP(t, apiAddrA, "call_remote_tool", map[string]any{
			"peer_id":   peerB,
			"tool_name": "mcp://code-reviewer/add",
			"arguments": map[string]any{},
		})
		if !strings.Contains(got, "fake-result:add") {
			t.Errorf("remote call returned %q, want the agent's own answer", got)
		}
	})
}

// startBoundaryServing runs a boundary for an agent that also serves.
func startBoundaryServing(t *testing.T, agentSocket, nodeSocket, agentID string, ingress *sambox.IngressManager) {
	t.Helper()

	egress, err := sambox.NewEgressPolicy(nil)
	if err != nil {
		t.Fatalf("NewEgressPolicy: %v", err)
	}
	listener, err := sambox.ListenSandboxSocket(agentSocket)
	if err != nil {
		t.Fatalf("ListenSandboxSocket: %v", err)
	}

	server := &sambox.SOCKS5Server{
		Dialer: &sambox.AgentDialer{
			Router:        &sambox.Router{Egress: egress},
			SidecarSocket: nodeSocket,
			AgentID:       agentID,
			Ingress:       ingress,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := server.Serve(ctx, listener); err != nil {
			t.Errorf("boundary: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}
