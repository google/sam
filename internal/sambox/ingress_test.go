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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/google/sam/api"
)

// registrationRecorder stands in for the node, capturing what the gateway asks
// it to advertise.
func registrationRecorder(t *testing.T, registrations chan<- *api.RegisterServiceRequest) string {
	t.Helper()
	return startFakeSidecar(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sam/service/register":
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				t.Errorf("reading registration: %v", err)
				return
			}
			var req api.RegisterServiceRequest
			if err := protojson.Unmarshal(body, &req); err != nil {
				t.Errorf("unmarshalling registration: %v", err)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			registrations <- &req
		case "/sam/service/unregister":
			// Accepted; the withdrawal path is covered by its own test.
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
}

func announce(t *testing.T, handler http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, ingressPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestIngressRegistersWhatTheAgentAnnounces covers the shape of the capability:
// the agent supplies liveness and a port, and the gateway supplies everything
// that would be dangerous for the agent to choose.
func TestIngressRegistersWhatTheAgentAnnounces(t *testing.T) {
	registrations := make(chan *api.RegisterServiceRequest, 1)
	socket := registrationRecorder(t, registrations)

	manager := &IngressManager{
		SidecarSocket: socket,
		Allowed:       []BundleIngress{{Name: "code-reviewer", Type: "mcp"}},
		// Registration never dials it, but a manager with no way into the
		// sandbox now refuses to register at all.
		AgentSocket: filepath.Join(t.TempDir(), "ingress.sock"),
	}
	t.Cleanup(func() { manager.Close(context.Background()) })

	rec := announce(t, manager.Handler(), `{"name":"code-reviewer","type":"mcp","port":8080}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204: %s", rec.Code, rec.Body)
	}

	got := <-registrations
	if got.GetService().GetName() != "code-reviewer" {
		t.Errorf("registered name = %q", got.GetService().GetName())
	}
	if got.GetService().GetType() != api.ServiceType_SERVICE_TYPE_MCP {
		t.Errorf("registered type = %v", got.GetService().GetType())
	}
	// The target is the gateway's own address, never anything the agent said.
	if target := got.GetTargetUrl(); !strings.HasPrefix(target, "http://127.0.0.1:") ||
		!strings.HasSuffix(target, "/code-reviewer") {
		t.Errorf("target_url = %q, want this gateway's own ingress address", target)
	}
}

// TestIngressRefusesNamesTheAgentWasNotGranted is the property that keeps an
// agent from advertising itself as somebody else's service.
func TestIngressRefusesNamesTheAgentWasNotGranted(t *testing.T) {
	registrations := make(chan *api.RegisterServiceRequest, 1)
	socket := registrationRecorder(t, registrations)

	manager := &IngressManager{
		SidecarSocket: socket,
		Allowed:       []BundleIngress{{Name: "code-reviewer", Type: "mcp"}},
		// Registration never dials it, but a manager with no way into the
		// sandbox now refuses to register at all.
		AgentSocket: filepath.Join(t.TempDir(), "ingress.sock"),
	}
	t.Cleanup(func() { manager.Close(context.Background()) })

	tests := []struct {
		name string
		body string
	}{
		{"a name it was not granted", `{"name":"payments","type":"mcp","port":8080}`},
		{"the right name with the wrong type", `{"name":"code-reviewer","type":"inference","port":8080}`},
		{"a port that is not a port", `{"name":"code-reviewer","type":"mcp","port":0}`},
		{"a port out of range", `{"name":"code-reviewer","type":"mcp","port":70000}`},
		{"a negative port", `{"name":"code-reviewer","type":"mcp","port":-1}`},
		{"nothing at all", `{}`},
		{"not json", `port 8080`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := announce(t, manager.Handler(), tc.body)
			if rec.Code == http.StatusNoContent {
				t.Fatalf("the gateway accepted %s", tc.body)
			}
			select {
			case reg := <-registrations:
				t.Fatalf("it registered %v anyway", reg)
			default:
			}
		})
	}
}

// TestIngressWithNoWayInRefusesRatherThanDiallingItsOwnNamespace is a
// vulnerability regression.
//
// There used to be a fallback: with no reverse channel, deliver to
// 127.0.0.1:<port>. That address is in the gateway's network namespace, which
// in a pod is the pod's -- sam-node's API, the other sidecars, every other
// boundary. The port comes from the agent. So an agent could announce a
// service whose backend was the node that vouches for it, and the mesh would
// route to it.
//
// Nothing is registered without a way into the sandbox, so there is no address
// for the mesh to reach and nothing for the agent to aim.
func TestIngressWithNoWayInRefusesRatherThanDiallingItsOwnNamespace(t *testing.T) {
	// Stands in for whatever else shares the gateway's namespace: the node's
	// API, a metrics endpoint, another agent's boundary.
	neighbour := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the gateway dialled a neighbour in its own network namespace")
		w.WriteHeader(http.StatusOK)
	}))
	defer neighbour.Close()

	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(neighbour.URL, "http://"))
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	registrations := make(chan *api.RegisterServiceRequest, 1)
	manager := &IngressManager{
		SidecarSocket: registrationRecorder(t, registrations),
		// Granted the name, so only the missing channel can refuse it.
		Allowed: []BundleIngress{{Name: "code-reviewer", Type: "mcp"}},
	}
	t.Cleanup(func() { manager.Close(context.Background()) })

	body := fmt.Sprintf(`{"name":"code-reviewer","type":"mcp","port":%d}`, port)
	rec := announce(t, manager.Handler(), body)
	if rec.Code == http.StatusNoContent {
		t.Fatalf("the agent announced a service aimed at the gateway's own namespace and was accepted")
	}

	select {
	case got := <-registrations:
		t.Fatalf("registered %q despite having no way into the sandbox", got.GetService().GetName())
	default:
	}
}

func TestIngressRefusesEverythingWhenNothingWasGranted(t *testing.T) {
	registrations := make(chan *api.RegisterServiceRequest, 1)
	manager := &IngressManager{SidecarSocket: registrationRecorder(t, registrations)}
	t.Cleanup(func() { manager.Close(context.Background()) })

	if rec := announce(t, manager.Handler(), `{"name":"anything","type":"mcp","port":8080}`); rec.Code == http.StatusNoContent {
		t.Fatal("an agent granted no ingress was allowed to serve")
	}
}

func TestIngressRejectsNonPost(t *testing.T) {
	manager := &IngressManager{}
	t.Cleanup(func() { manager.Close(context.Background()) })

	req := httptest.NewRequest(http.MethodGet, ingressPath, nil)
	rec := httptest.NewRecorder()
	manager.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

// TestIngressForwardsIntoTheSandbox covers the other direction: what the node
// delivers reaches the agent, with the service name the gateway added stripped
// back off so the agent sees the path it published.
func TestIngressForwardsIntoTheSandbox(t *testing.T) {
	registrations := make(chan *api.RegisterServiceRequest, 1)
	socket := registrationRecorder(t, registrations)

	paths := make(chan string, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		_, _ = io.WriteString(w, "served by the agent")
	}))
	defer agent.Close()

	manager := &IngressManager{
		SidecarSocket: socket,
		Allowed:       []BundleIngress{{Name: "code-reviewer", Type: "mcp"}},
		// The sandbox here is an ordinary server, so the port the agent
		// announces is reached at the test server's address.
		AgentAddr: func(int) string { return strings.TrimPrefix(agent.URL, "http://") },
	}
	t.Cleanup(func() { manager.Close(context.Background()) })

	if rec := announce(t, manager.Handler(), `{"name":"code-reviewer","type":"mcp","port":8080}`); rec.Code != http.StatusNoContent {
		t.Fatalf("announce: %d %s", rec.Code, rec.Body)
	}
	target := (<-registrations).GetTargetUrl()

	resp, err := http.Get(target + "/review")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if string(body) != "served by the agent" {
		t.Errorf("body = %q", body)
	}
	if got := <-paths; got != "/review" {
		t.Errorf("the agent saw %q, want the service name stripped", got)
	}
}

func TestIngressRefusesToRouteAnUnknownService(t *testing.T) {
	manager := &IngressManager{
		SidecarSocket: registrationRecorder(t, make(chan *api.RegisterServiceRequest, 1)),
		Allowed:       []BundleIngress{{Name: "code-reviewer", Type: "mcp"}},
	}
	t.Cleanup(func() { manager.Close(context.Background()) })

	addr, err := manager.ensureListening()
	if err != nil {
		t.Fatalf("ensureListening: %v", err)
	}

	resp, err := http.Get("http://" + addr + "/never-announced/anything")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		t.Error("the gateway routed a service nobody announced")
	}
}

// TestIngressWithdrawsOnClose: a detached sandbox must stop being routed to,
// rather than lingering in discovery until something times out.
func TestIngressWithdrawsOnClose(t *testing.T) {
	registrations := make(chan *api.RegisterServiceRequest, 1)
	withdrawals := make(chan string, 1)

	socket := startFakeSidecar(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sam/service/register":
			registrations <- nil
		case "/sam/service/unregister":
			var body map[string]string
			_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
			withdrawals <- body["name"]
		}
	}))

	manager := &IngressManager{
		SidecarSocket: socket,
		Allowed:       []BundleIngress{{Name: "code-reviewer", Type: "mcp"}},
		// Registration never dials it, but a manager with no way into the
		// sandbox now refuses to register at all.
		AgentSocket: filepath.Join(t.TempDir(), "ingress.sock"),
	}
	if rec := announce(t, manager.Handler(), `{"name":"code-reviewer","type":"mcp","port":8080}`); rec.Code != http.StatusNoContent {
		t.Fatalf("announce: %d", rec.Code)
	}
	<-registrations

	manager.Close(context.Background())
	if got := <-withdrawals; got != "code-reviewer" {
		t.Errorf("withdrew %q, want code-reviewer", got)
	}
}

func TestSplitServicePath(t *testing.T) {
	tests := []struct {
		path     string
		wantName string
		wantRest string
	}{
		{"/code-reviewer/review", "code-reviewer", "/review"},
		{"/code-reviewer", "code-reviewer", "/"},
		{"/code-reviewer/", "code-reviewer", "/"},
		{"/code-reviewer/a/b", "code-reviewer", "/a/b"},
		{"/", "", "/"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			name, rest := splitServicePath(tc.path)
			if name != tc.wantName || rest != tc.wantRest {
				t.Errorf("splitServicePath(%q) = %q, %q; want %q, %q", tc.path, name, rest, tc.wantName, tc.wantRest)
			}
		})
	}
}
