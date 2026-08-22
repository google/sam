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

package api

import "testing"

func TestParseMeshHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		want    string
		wantErr bool
	}{
		{"inference service", "openrouter.inference.sam.alt", "inference://openrouter", false},
		{"mcp service", "code-reviewer.mcp.sam.alt", "mcp://code-reviewer", false},
		{"trailing root dot", "calculator.mcp.sam.alt.", "mcp://calculator", false},
		{"uppercase is folded", "Calculator.MCP.Sam.Alt", "mcp://calculator", false},
		{"dotted service name", "my-service.local.mcp.sam.alt", "mcp://my-service.local", false},
		{"underscore service name", "my_service.mcp.sam.alt", "mcp://my_service", false},

		{"local node is not a service", "mesh.sam.alt", "", true},
		{"unknown service type", "thing.storage.sam.alt", "", true},
		{"missing service type", "calculator.sam.alt", "", true},
		{"zone only", "sam.alt", "", true},
		{"outside the zone", "api.github.com", "", true},
		{"zone as a substring", "evil-sam.alt", "", true},
		{"empty service name", ".mcp.sam.alt", "", true},
		{"empty", "", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseMeshHost(tc.host)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseMeshHost(%q) = %q, want error", tc.host, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMeshHost(%q) returned error: %v", tc.host, err)
			}
			if got != tc.want {
				t.Errorf("ParseMeshHost(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

func TestMeshHostRoundTrip(t *testing.T) {
	tests := []struct {
		svcType ServiceType
		name    string
		want    string
		wantURI string
	}{
		{ServiceType_SERVICE_TYPE_MCP, "calculator", "calculator.mcp.sam.alt", "mcp://calculator"},
		{ServiceType_SERVICE_TYPE_INFERENCE, "openrouter", "openrouter.inference.sam.alt", "inference://openrouter"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, err := MeshHost(tc.svcType, tc.name)
			if err != nil {
				t.Fatalf("MeshHost(%v, %q) returned error: %v", tc.svcType, tc.name, err)
			}
			if host != tc.want {
				t.Fatalf("MeshHost(%v, %q) = %q, want %q", tc.svcType, tc.name, host, tc.want)
			}
			uri, err := ParseMeshHost(host)
			if err != nil {
				t.Fatalf("ParseMeshHost(%q) returned error: %v", host, err)
			}
			if uri != tc.wantURI {
				t.Errorf("round trip of %q = %q, want %q", tc.name, uri, tc.wantURI)
			}
		})
	}
}

func TestMeshHostRejects(t *testing.T) {
	tests := []struct {
		name    string
		svcType ServiceType
		svcName string
	}{
		{"unspecified type", ServiceType_SERVICE_TYPE_UNSPECIFIED, "calculator"},
		{"empty name", ServiceType_SERVICE_TYPE_MCP, ""},
		{"uppercase name is not addressable", ServiceType_SERVICE_TYPE_MCP, "Calculator"},
		{"name with a path", ServiceType_SERVICE_TYPE_MCP, "calculator/add"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if host, err := MeshHost(tc.svcType, tc.svcName); err == nil {
				t.Fatalf("MeshHost(%v, %q) = %q, want error", tc.svcType, tc.svcName, host)
			}
		})
	}
}

func TestIsMeshHostAndIsMeshEntrypointHost(t *testing.T) {
	tests := []struct {
		host    string
		isMesh  bool
		isEntry bool
	}{
		{"mesh.sam.alt", true, true},
		{"MESH.SAM.ALT.", true, true},
		{"calculator.mcp.sam.alt", true, false},
		{"sam.alt", true, false},
		{"node.sam.alt", true, false},
		{"api.github.com", false, false},
		{"evil-sam.alt", false, false},
		{"mesh.sam.alt.evil.com", false, false},
		{"", false, false},
	}

	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			if got := IsMeshHost(tc.host); got != tc.isMesh {
				t.Errorf("IsMeshHost(%q) = %v, want %v", tc.host, got, tc.isMesh)
			}
			if got := IsMeshEntrypointHost(tc.host); got != tc.isEntry {
				t.Errorf("IsMeshEntrypointHost(%q) = %v, want %v", tc.host, got, tc.isEntry)
			}
		})
	}
}
