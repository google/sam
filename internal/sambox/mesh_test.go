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
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/sam/api"
)

// startFakeSidecar serves the two endpoints sam-box uses on a Unix socket:
// service discovery, and the egress proxy path it rewrites onto.
func startFakeSidecar(t *testing.T, h http.Handler) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "sambox")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "sidecar.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := httptest.NewUnstartedServer(h)
	_ = srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)

	return path
}

func discoverHandler(t *testing.T, peerID string, seen *chan string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sam/service/discover":
			providers := []*api.DiscoveredProvider{}
			if peerID != "" {
				providers = append(providers, &api.DiscoveredProvider{
					PeerId:  peerID,
					SrvName: r.URL.Query().Get("name"),
				})
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(providers); err != nil {
				t.Errorf("encode providers: %v", err)
			}
		default:
			if seen != nil {
				select {
				case *seen <- r.URL.Path:
				default:
				}
			}
			_, _ = io.WriteString(w, "reached")
		}
	})
}

// clientOver speaks HTTP over an already-established connection, the way an
// agent's HTTP client speaks over the connection SOCKS5 handed it.
func clientOver(conn net.Conn) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil },
		},
	}
}

// TestMeshServiceRequestIsRewrittenOntoTheSidecarPath is the point of this
// path: a name resolves to a provider, and the agent's request comes out on
// /sam/<peer>/<type>/<name>/<path> without the agent knowing any of it.
func TestMeshServiceRequestIsRewrittenOntoTheSidecarPath(t *testing.T) {
	seen := make(chan string, 1)
	socket := startFakeSidecar(t, discoverHandler(t, "12D3KooWtestpeer", &seen))

	d := &AgentDialer{Router: &Router{}, SidecarSocket: socket}
	conn, err := d.DialDestination(context.Background(), nil, Destination{
		Name:   "openrouter.inference.sam.alt",
		Port:   80,
		IsName: true,
	})
	if err != nil {
		t.Fatalf("DialDestination: %v", err)
	}
	defer func() { _ = conn.Close() }()

	resp, err := clientOver(conn).Get("http://openrouter.inference.sam.alt/v1/models")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %s, want 200", resp.Status)
	}

	got := <-seen
	if want := "/sam/12D3KooWtestpeer/inference/openrouter/v1/models"; got != want {
		t.Errorf("sidecar saw %q, want %q", got, want)
	}
}

func TestMeshServiceWithNoProviderIsUnreachable(t *testing.T) {
	socket := startFakeSidecar(t, discoverHandler(t, "", nil))

	d := &AgentDialer{Router: &Router{}, SidecarSocket: socket}
	_, err := d.DialDestination(context.Background(), nil, Destination{
		Name:   "missing.mcp.sam.alt",
		Port:   80,
		IsName: true,
	})
	if !errors.Is(err, ErrHostUnreachable) {
		t.Fatalf("DialDestination = %v, want ErrHostUnreachable", err)
	}
	if code := replyCodeFor(err); code != replyHostUnreachable {
		t.Errorf("reply code = %#x, want %#x", code, replyHostUnreachable)
	}
}

// TestMalformedMeshNameIsDeniedNotReportedMissing keeps the two failures
// distinct: a name that cannot be a service is a policy denial, so the boundary
// does not confirm what does or does not exist in the mesh.
func TestMalformedMeshNameIsDeniedNotReportedMissing(t *testing.T) {
	socket := startFakeSidecar(t, discoverHandler(t, "12D3KooWtestpeer", nil))

	d := &AgentDialer{Router: &Router{}, SidecarSocket: socket}
	_, err := d.DialDestination(context.Background(), nil, Destination{
		Name:   "whatever.sam.alt",
		Port:   80,
		IsName: true,
	})
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("DialDestination = %v, want ErrNotAllowed", err)
	}
}

func TestMeshServiceRequiresASidecarSocket(t *testing.T) {
	d := &AgentDialer{Router: &Router{}}
	_, err := d.DialDestination(context.Background(), nil, Destination{
		Name:   "openrouter.inference.sam.alt",
		Port:   80,
		IsName: true,
	})
	if err == nil {
		t.Fatal("DialDestination with no sidecar socket succeeded, want an error")
	}
}

func TestUnreachableSidecarIsReportedAsUnreachable(t *testing.T) {
	dir, err := os.MkdirTemp("", "sambox")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	d := &AgentDialer{Router: &Router{}, SidecarSocket: filepath.Join(dir, "absent.sock")}
	_, err = d.DialDestination(context.Background(), nil, Destination{
		Name:   "openrouter.inference.sam.alt",
		Port:   80,
		IsName: true,
	})
	if !errors.Is(err, ErrHostUnreachable) {
		t.Fatalf("DialDestination = %v, want ErrHostUnreachable", err)
	}
}
