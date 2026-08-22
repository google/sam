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

package sambox

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/google/sam/api"
	"golang.org/x/net/proxy"
)

type sidecarCall struct {
	path    string
	headers http.Header
}

// recordingSidecar answers anything and reports what it was asked for, so a
// test can assert both what reached the node and what did not.
func recordingSidecar(t *testing.T) (socket string, calls chan sidecarCall) {
	t.Helper()
	calls = make(chan sidecarCall, 8)
	socket = startFakeSidecar(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case calls <- sidecarCall{path: r.URL.Path, headers: r.Header.Clone()}:
		default:
			t.Errorf("unexpected extra call to %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	return socket, calls
}

func entrypointClient(t *testing.T, socket string) *http.Client {
	t.Helper()
	return entrypointClientForAgent(t, socket, "")
}

func entrypointClientForAgent(t *testing.T, socket, agentID string) *http.Client {
	t.Helper()
	boundary := startSOCKS5(t, &SOCKS5Server{
		Dialer: &AgentDialer{Router: &Router{}, SidecarSocket: socket, AgentID: agentID},
	})
	dialer, err := proxy.SOCKS5("unix", boundary, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("proxy.SOCKS5: %v", err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		t.Fatal("SOCKS5 dialer does not implement ContextDialer")
	}
	return &http.Client{Transport: &http.Transport{DialContext: contextDialer.DialContext}}
}

// TestAgentIdentityIsAssertedToTheNode covers the half of admission that makes
// an agent visible to mesh policy: the gateway names the principal, because it
// is the only party that knows which agent a flow belongs to.
func TestAgentIdentityIsAssertedToTheNode(t *testing.T) {
	socket, calls := recordingSidecar(t)
	client := entrypointClientForAgent(t, socket, "reviewer-7.prod.acme.example")

	resp, err := client.Get("http://" + api.MeshEntrypointHost + "/v1/models")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()

	if got := (<-calls).headers.Get(api.HeaderSamAgent); got != "reviewer-7.prod.acme.example" {
		t.Errorf("%s = %q, want the agent the gateway serves", api.HeaderSamAgent, got)
	}
}

// TestAgentCannotForgeItsIdentity is the other half. An agent that could set
// the header would be able to borrow any other agent's authority, so the
// gateway overwrites it rather than merging with it.
func TestAgentCannotForgeItsIdentity(t *testing.T) {
	t.Run("a different agent", func(t *testing.T) {
		socket, calls := recordingSidecar(t)
		client := entrypointClientForAgent(t, socket, "reviewer-7.prod.acme.example")

		req, err := http.NewRequest(http.MethodGet, "http://"+api.MeshEntrypointHost+"/v1/models", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set(api.HeaderSamAgent, "privileged.prod.acme.example")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = resp.Body.Close()

		if got := (<-calls).headers.Get(api.HeaderSamAgent); got != "reviewer-7.prod.acme.example" {
			t.Errorf("%s = %q, want the forged value replaced", api.HeaderSamAgent, got)
		}
	})

	t.Run("any agent at all when the boundary has none", func(t *testing.T) {
		socket, calls := recordingSidecar(t)
		client := entrypointClient(t, socket)

		req, err := http.NewRequest(http.MethodGet, "http://"+api.MeshEntrypointHost+"/v1/models", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set(api.HeaderSamAgent, "privileged.prod.acme.example")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = resp.Body.Close()

		if got := (<-calls).headers.Get(api.HeaderSamAgent); got != "" {
			t.Errorf("%s = %q, want it stripped entirely", api.HeaderSamAgent, got)
		}
	})
}

// TestAgentReachesInferenceAndTools covers what an agent is supposed to have:
// the mesh's inference and tool endpoints, reached by name, over SOCKS5.
func TestAgentReachesInferenceAndTools(t *testing.T) {
	socket, calls := recordingSidecar(t)
	client := entrypointClient(t, socket)

	for _, path := range []string{"/v1/models", "/v1/chat/completions", "/v1/completions", "/mcp"} {
		resp, err := client.Get("http://" + api.MeshEntrypointHost + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %s, want 200", path, resp.Status)
		}
		if got := (<-calls).path; got != path {
			t.Errorf("node saw %q, want %q", got, path)
		}
	}
}

// TestAgentCannotReachTheNodeAPI is the separation this boundary exists for.
// The node's sidecar is an operator surface: registering a service would let an
// agent advertise itself into the mesh under the node's identity and choose the
// URL the mesh then routes to, and the raw egress proxy would let it reach any
// peer and service it names. Nothing here may reach the node at all.
func TestAgentCannotReachTheNodeAPI(t *testing.T) {
	socket, calls := recordingSidecar(t)
	client := entrypointClient(t, socket)

	forbidden := []string{
		"/sam/service/register",
		"/sam/service/unregister",
		"/sam/service/discover",
		"/sam/12D3KooWsomepeer/mcp/anything",
		"/metrics",
		"/healthz",
		"/readyz",
		"/",
		"/v1/embeddings",
		"/mcpsomething",
	}

	for _, path := range forbidden {
		resp, err := client.Get("http://" + api.MeshEntrypointHost + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s: status %s, want 403", path, resp.Status)
		}
	}

	select {
	case call := <-calls:
		t.Fatalf("the node was reached at %q; an agent must not reach it at all", call.path)
	default:
	}
}

// TestEntrypointStripsAssertedIdentityHeaders pins that an agent cannot claim
// an identity by setting the headers the node honours.
func TestEntrypointStripsAssertedIdentityHeaders(t *testing.T) {
	socket, calls := recordingSidecar(t)
	client := entrypointClient(t, socket)

	req, err := http.NewRequest(http.MethodGet, "http://"+api.MeshEntrypointHost+"/v1/models", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set(api.HeaderSamBiscuit, "forged-mesh-credential")
	req.Header.Set(api.HeaderSamAuthentication, "Bearer forged-node-token")
	req.Header.Set("Authorization", "Bearer the-agents-own-backend-credential")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	call := <-calls
	if got := call.headers.Get(api.HeaderSamBiscuit); got != "" {
		t.Errorf("%s reached the node as %q, want it stripped", api.HeaderSamBiscuit, got)
	}
	if got := call.headers.Get(api.HeaderSamAuthentication); got != "" {
		t.Errorf("%s reached the node as %q, want it stripped", api.HeaderSamAuthentication, got)
	}
	// Authorization means the destination service's own credential, so it is
	// the agent's to send and must survive.
	if got := call.headers.Get("Authorization"); got != "Bearer the-agents-own-backend-credential" {
		t.Errorf("Authorization = %q, want it forwarded untouched", got)
	}
}

// TestEntrypointIgnoresTheRequestedPort pins that the entrypoint is a name for
// a surface, not for an address.
func TestEntrypointIgnoresTheRequestedPort(t *testing.T) {
	socket, _ := recordingSidecar(t)
	d := &AgentDialer{Router: &Router{}, SidecarSocket: socket}

	for _, port := range []uint16{80, 443, 8080} {
		conn, err := d.DialDestination(context.Background(), nil, Destination{
			Name:   api.MeshEntrypointHost,
			Port:   port,
			IsName: true,
		})
		if err != nil {
			t.Fatalf("port %d: %v", port, err)
		}
		_ = conn.Close()
	}
}

func TestEntrypointRequiresASidecarSocket(t *testing.T) {
	d := &AgentDialer{Router: &Router{}}
	if _, err := d.DialDestination(context.Background(), nil, Destination{
		Name:   api.MeshEntrypointHost,
		Port:   80,
		IsName: true,
	}); err == nil {
		t.Fatal("DialDestination with no sidecar socket succeeded, want an error")
	}
}

func TestAgentMayReach(t *testing.T) {
	allowed := []string{"/v1/models", "/v1/chat/completions", "/v1/completions", "/mcp", "/mcp/session"}
	for _, path := range allowed {
		if !agentMayReach(path) {
			t.Errorf("agentMayReach(%q) = false, want true", path)
		}
	}

	denied := []string{"", "/", "/v1", "/v1/", "/v1/models/extra", "/mcpsomething", "/sam/service/register", "/metrics"}
	for _, path := range denied {
		if agentMayReach(path) {
			t.Errorf("agentMayReach(%q) = true, want false", path)
		}
	}
}
