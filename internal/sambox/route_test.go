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
	"errors"
	"testing"
)

// TestZeroRouterDeniesEverythingExternal pins the fail-closed default: a
// sam-box configured with no egress policy must not be an open proxy.
func TestZeroRouterDeniesEverythingExternal(t *testing.T) {
	var r Router
	for _, host := range []string{"api.github.com", "127.0.0.1", "localhost", "example.com"} {
		if _, err := r.Route(Destination{Name: host, Port: 443, IsName: true}); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("Route(%q) with no policy = %v, want ErrNotAllowed", host, err)
		}
	}
}

func TestRouteClassification(t *testing.T) {
	policy, err := NewEgressPolicy([]string{"api.github.com", "*.pypi.org", "192.0.2.10"})
	if err != nil {
		t.Fatalf("NewEgressPolicy: %v", err)
	}
	r := &Router{Egress: policy}

	tests := []struct {
		name       string
		host       string
		wantKind   RouteKind
		wantURI    string
		wantDenied bool
	}{
		{"mesh entrypoint", "mesh.sam.alt", RouteMeshEntrypoint, "", false},
		{"mesh entrypoint is case-insensitive", "MESH.SAM.ALT", RouteMeshEntrypoint, "", false},
		{"mesh inference service", "openrouter.inference.sam.alt", RouteMeshService, "inference://openrouter", false},
		{"mesh mcp service", "code-reviewer.mcp.sam.alt", RouteMeshService, "mcp://code-reviewer", false},
		{"allowlisted host", "api.github.com", RouteExternal, "", false},
		{"allowlisted wildcard subdomain", "files.pypi.org", RouteExternal, "", false},
		{"allowlisted literal address", "192.0.2.10", RouteExternal, "", false},

		{"unknown external host", "evil.example", 0, "", true},
		{"mesh zone but no service type", "whatever.sam.alt", 0, "", true},
		{"mesh zone with unknown service type", "thing.storage.sam.alt", 0, "", true},
		{"bare mesh zone", "sam.alt", 0, "", true},
		{"lookalike of the mesh zone", "evil-sam.alt", 0, "", true},
		{"lookalike of an allowlisted host", "evil-api.github.com", 0, "", true},
		{"wildcard parent is not covered", "pypi.org", 0, "", true},
		{"lookalike of a wildcard parent", "evilpypi.org", 0, "", true},
		{"unlisted literal address", "192.0.2.11", 0, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := r.Route(Destination{Name: tc.host, Port: 443, IsName: true})
			if tc.wantDenied {
				if !errors.Is(err, ErrNotAllowed) {
					t.Fatalf("Route(%q) = %+v, %v; want ErrNotAllowed", tc.host, got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Route(%q) returned error: %v", tc.host, err)
			}
			if got.Kind != tc.wantKind {
				t.Errorf("Route(%q) kind = %v, want %v", tc.host, got.Kind, tc.wantKind)
			}
			if got.ServiceURI != tc.wantURI {
				t.Errorf("Route(%q) service = %q, want %q", tc.host, got.ServiceURI, tc.wantURI)
			}
			if got.Destination.Name != tc.host {
				t.Errorf("Route(%q) lost the destination: %+v", tc.host, got.Destination)
			}
		})
	}
}

// TestMeshNamesIgnoreEgressPolicy pins that mesh routing is not reachable
// through the allowlist: a mesh name is authorized by mesh policy, and an
// operator listing it under egress must not change how it is routed.
func TestMeshNamesIgnoreEgressPolicy(t *testing.T) {
	policy, err := NewEgressPolicy([]string{"*.sam.alt"})
	if err != nil {
		t.Fatalf("NewEgressPolicy: %v", err)
	}
	r := &Router{Egress: policy}

	got, err := r.Route(Destination{Name: "openrouter.inference.sam.alt", Port: 80, IsName: true})
	if err != nil {
		t.Fatalf("Route returned error: %v", err)
	}
	if got.Kind != RouteMeshService {
		t.Errorf("kind = %v, want %v", got.Kind, RouteMeshService)
	}

	if _, err := r.Route(Destination{Name: "nothing.sam.alt", Port: 80, IsName: true}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("a non-service mesh name was allowed by the egress list: %v", err)
	}
}

func TestNewEgressPolicyRejectsAmbiguousEntries(t *testing.T) {
	tests := []struct {
		name  string
		entry string
	}{
		{"empty", ""},
		{"bare wildcard", "*"},
		{"trailing wildcard", "github.*"},
		{"infix wildcard", "api.*.com"},
		{"partial label wildcard", "*api.github.com"},
		{"double wildcard", "*.*.github.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewEgressPolicy([]string{tc.entry}); err == nil {
				t.Fatalf("NewEgressPolicy(%q) = nil error, want a rejection", tc.entry)
			}
		})
	}
}

func TestEgressPolicyNormalizesEntriesAndHosts(t *testing.T) {
	policy, err := NewEgressPolicy([]string{"API.GitHub.com.", "*.PyPI.org"})
	if err != nil {
		t.Fatalf("NewEgressPolicy: %v", err)
	}

	for _, host := range []string{"api.github.com", "API.GITHUB.COM", "api.github.com.", "files.PyPI.org."} {
		if !policy.Allows(host) {
			t.Errorf("Allows(%q) = false, want true", host)
		}
	}
	if policy.Allows("") {
		t.Error("Allows(\"\") = true, want false")
	}
}
