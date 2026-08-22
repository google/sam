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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/proxy"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/sambox"
)

// TestSandboxBoundaryCUJ drives the sandbox boundary the way an agent does:
// a SOCKS5 client on a Unix socket, no credential of any kind, addressing
// everything by name. Node A provides the services, node B is the node the
// gateway consumes, and the agent must reach the mesh through the gateway
// while never reaching node B's own API.
//
// One mesh is set up for the whole test: the cases are cheap, the mesh is not.
func TestSandboxBoundaryCUJ(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	_, hubAddr := startMockRouter(t)

	homeA := t.TempDir()
	homeB := t.TempDir()
	apiToken := "test-token"

	// Not t.TempDir(): socket paths have a ~104 byte kernel budget and test
	// names spend it quickly.
	sockDir, err := os.MkdirTemp("", "boundary")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	nodeSocket := filepath.Join(sockDir, "node.sock")
	agentSocket := filepath.Join(sockDir, "agent.sock")

	t.Log("Starting node A (provider) and node B (the gateway's node)...")
	_ = startBackgroundNode(t, nodeBin, hubAddr, homeA,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--discovery-interval", "100ms",
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
	peerA := extractPeerID(addrA)
	callMCP(t, apiAddrB, "connect_peer", map[string]any{"peer_addr": addrA})
	waitForDHTPeers(t, apiAddrA)

	inference := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"test-model"}]}`))
		case "/v1/chat/completions":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"cmpl-1","object":"chat.completion","model":"test-model",` +
				`"choices":[{"index":0,"message":{"role":"assistant","content":"hello from the mesh"}}]}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer inference.Close()

	tools := httptest.NewServer(newBoundaryMCPHandler(t))
	defer tools.Close()

	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "external ok")
	}))
	defer external.Close()

	registerInferenceService(t, apiAddrA, apiToken, "test-llm", inference.URL)
	registerService(t, apiAddrA, apiToken, "calc", tools.URL)

	// The model reaching node B's facade means A's registration has propagated,
	// so the boundary cases below do not each have to wait for discovery.
	waitForFacadeModel(t, apiAddrB, apiToken, "test-model")

	startBoundary(t, agentSocket, nodeSocket, "127.0.0.1")
	client := boundaryClient(t, agentSocket)

	t.Run("requests", func(t *testing.T) {
		tests := []struct {
			name string
			// A refused destination fails the SOCKS5 handshake, so the request
			// errors instead of returning a status.
			wantRefused  bool
			method       string
			url          string
			body         string
			wantStatus   int
			wantContains string
		}{
			{
				name:         "inference is served across the mesh",
				method:       http.MethodPost,
				url:          "http://" + api.MeshEntrypointHost + "/v1/chat/completions",
				body:         `{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`,
				wantStatus:   http.StatusOK,
				wantContains: "hello from the mesh",
			},
			{
				name:         "the mesh's models are listed",
				method:       http.MethodGet,
				url:          "http://" + api.MeshEntrypointHost + "/v1/models",
				wantStatus:   http.StatusOK,
				wantContains: "test-model",
			},
			{
				name:         "a service can be addressed by its own name",
				method:       http.MethodGet,
				url:          "http://test-llm.inference." + api.MeshZone + "/v1/models",
				wantStatus:   http.StatusOK,
				wantContains: "test-model",
			},
			{
				name:         "an allowlisted destination is reachable",
				method:       http.MethodGet,
				url:          external.URL,
				wantStatus:   http.StatusOK,
				wantContains: "external ok",
			},

			{name: "an unlisted destination is refused", wantRefused: true, method: http.MethodGet, url: "http://blocked.example/"},
			{name: "a mesh name with no service is refused", wantRefused: true, method: http.MethodGet, url: "http://nothing." + api.MeshZone + "/"},
			{name: "a service nobody provides is refused", wantRefused: true, method: http.MethodGet, url: "http://absent.mcp." + api.MeshZone + "/"},

			// The node's own API. Every one of these must be answered by the
			// gateway, not forwarded: registering would let an agent advertise
			// itself into the mesh under the node's identity and name the URL
			// the mesh routes to, and the raw proxy would let it reach any peer
			// and service it names.
			{name: "the node's register endpoint", method: http.MethodPost, url: "http://" + api.MeshEntrypointHost + "/sam/service/register", body: "{}", wantStatus: http.StatusForbidden},
			{name: "the node's unregister endpoint", method: http.MethodPost, url: "http://" + api.MeshEntrypointHost + "/sam/service/unregister", body: "{}", wantStatus: http.StatusForbidden},
			{name: "the node's discovery endpoint", method: http.MethodGet, url: "http://" + api.MeshEntrypointHost + "/sam/service/discover?type=mcp&name=calc", wantStatus: http.StatusForbidden},
			{name: "the node's raw egress proxy", method: http.MethodGet, url: "http://" + api.MeshEntrypointHost + "/sam/" + peerA + "/mcp/calc", wantStatus: http.StatusForbidden},
			{name: "the node's metrics", method: http.MethodGet, url: "http://" + api.MeshEntrypointHost + "/metrics", wantStatus: http.StatusForbidden},
			{name: "the node's health", method: http.MethodGet, url: "http://" + api.MeshEntrypointHost + "/healthz", wantStatus: http.StatusForbidden},
			{name: "the node's root", method: http.MethodGet, url: "http://" + api.MeshEntrypointHost + "/", wantStatus: http.StatusForbidden},
			{name: "an unserved inference path", method: http.MethodGet, url: "http://" + api.MeshEntrypointHost + "/v1/embeddings", wantStatus: http.StatusForbidden},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				var bodyReader io.Reader
				if tc.body != "" {
					bodyReader = strings.NewReader(tc.body)
				}
				req, err := http.NewRequest(tc.method, tc.url, bodyReader)
				if err != nil {
					t.Fatalf("NewRequest: %v", err)
				}
				req.Header.Set("Content-Type", "application/json")

				resp, err := client.Do(req)
				if tc.wantRefused {
					if err == nil {
						_ = resp.Body.Close()
						t.Fatalf("%s returned %s, want the boundary to refuse it", tc.url, resp.Status)
					}
					return
				}
				if err != nil {
					t.Fatalf("%s: %v", tc.url, err)
				}
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != tc.wantStatus {
					t.Errorf("status = %s, want %d", resp.Status, tc.wantStatus)
				}
				if tc.wantContains != "" {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
					if !strings.Contains(string(body), tc.wantContains) {
						t.Errorf("body = %q, want it to contain %q", body, tc.wantContains)
					}
				}
			})
		}
	})

	// The flagship path: an agent with no credential discovers a tool on
	// another node and invokes it, all through the boundary.
	t.Run("remote tool call", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		session := connectMCPThroughBoundary(t, ctx, client)
		defer func() { _ = session.Close() }()

		res, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name: "call_remote_tool",
			Arguments: map[string]any{
				"peer_id":   peerA,
				"tool_name": "mcp://calc/add",
				"arguments": map[string]any{"a": 2, "b": 3},
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
		if !strings.Contains(got, "fake-result:add") {
			t.Errorf("tool result = %q, want it to contain %q", got, "fake-result:add")
		}
	})
}

// startBoundary runs the sandbox boundary in process, which is all sam-box
// does: it holds no identity and no mesh connection of its own.
func startBoundary(t *testing.T, agentSocket, nodeSocket string, egressAllow ...string) {
	t.Helper()
	startBoundaryWith(t, agentSocket, nodeSocket, "", egressAllow)
}

// startBoundaryForAgent serves one named agent, as an admitted sandbox does.
func startBoundaryForAgent(t *testing.T, agentSocket, nodeSocket, agentID string) {
	t.Helper()
	startBoundaryWith(t, agentSocket, nodeSocket, agentID, nil)
}

func startBoundaryWith(t *testing.T, agentSocket, nodeSocket, agentID string, egressAllow []string) {
	t.Helper()

	egress, err := sambox.NewEgressPolicy(egressAllow)
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

// boundaryClient is an ordinary HTTP client that happens to reach the network
// through the sandbox socket, which is exactly what an agent's client is.
func boundaryClient(t *testing.T, agentSocket string) *http.Client {
	t.Helper()

	dialer, err := proxy.SOCKS5("unix", agentSocket, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("proxy.SOCKS5: %v", err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		t.Fatal("SOCKS5 dialer does not implement ContextDialer")
	}
	return &http.Client{
		Transport: &http.Transport{DialContext: contextDialer.DialContext},
		Timeout:   20 * time.Second,
	}
}

func connectMCPThroughBoundary(t *testing.T, ctx context.Context, client *http.Client) *mcp.ClientSession {
	t.Helper()

	// No credential is set anywhere: an agent has none, and the boundary is
	// what makes the mesh reachable without one.
	session, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0.1.0"}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:   "http://" + api.MeshEntrypointHost + "/mcp",
			HTTPClient: client,
		}, nil)
	if err != nil {
		t.Fatalf("connecting to the mesh over the boundary: %v", err)
	}
	return session
}

func newBoundaryMCPHandler(t *testing.T) http.Handler {
	t.Helper()

	srv := mcp.NewServer(&mcp.Implementation{Name: "calc", Version: "0.0.1"}, nil)
	srv.AddTool(&mcp.Tool{
		Name:        "add",
		Description: "add two numbers",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "fake-result:add"}},
		}, nil
	})
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
}
