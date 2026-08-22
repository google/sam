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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBundle(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLoadAgentBundle(t *testing.T) {
	path := writeBundle(t, `
version: v1
agent:
  id: reviewer-7.prod.acme.example
  external_id: spiffe://acme.example/prod/reviewer-7
egress:
  allow:
    - api.github.com
    - "*.pypi.org"
`)

	bundle, err := LoadAgentBundle(path)
	if err != nil {
		t.Fatalf("LoadAgentBundle: %v", err)
	}
	if bundle.Agent.ID != "reviewer-7.prod.acme.example" {
		t.Errorf("agent id = %q", bundle.Agent.ID)
	}
	if bundle.Agent.ExternalID != "spiffe://acme.example/prod/reviewer-7" {
		t.Errorf("external id = %q, want it kept verbatim", bundle.Agent.ExternalID)
	}
	if !bundle.EgressPolicy().Allows("files.pypi.org") {
		t.Error("compiled egress policy does not allow files.pypi.org")
	}
	if bundle.EgressPolicy().Allows("pypi.org") {
		t.Error("a wildcard covered its parent domain")
	}
}

func TestLoadAgentBundleWithNoEgressAllowsNothing(t *testing.T) {
	path := writeBundle(t, `
version: v1
agent:
  id: reviewer.acme.example
`)

	bundle, err := LoadAgentBundle(path)
	if err != nil {
		t.Fatalf("LoadAgentBundle: %v", err)
	}
	for _, host := range []string{"api.github.com", "example.com", "127.0.0.1"} {
		if bundle.EgressPolicy().Allows(host) {
			t.Errorf("a bundle declaring no egress allowed %s", host)
		}
	}
}

// TestLoadAgentBundleRejects covers the reason parsing is strict: a bundle is a
// security document, and a field that silently reads as absent grants either
// more access than intended or an identity nobody issued.
func TestLoadAgentBundleRejects(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "no version",
			content: "agent:\n  id: reviewer.acme.example\n",
			wantErr: "version",
		},
		{
			name:    "a version this gateway does not understand",
			content: "version: v2\nagent:\n  id: reviewer.acme.example\n",
			wantErr: "version",
		},
		{
			name:    "no agent id",
			content: "version: v1\nagent:\n  external_id: spiffe://acme.example/x\n",
			wantErr: "empty",
		},
		{
			name:    "an agent id with no authority",
			content: "version: v1\nagent:\n  id: reviewer\n",
			wantErr: "authority",
		},
		{
			name:    "an agent id that is a pattern",
			content: "version: v1\nagent:\n  id: \"*.acme.example\"\n",
			wantErr: "wildcard",
		},
		{
			name:    "a misspelled field",
			content: "version: v1\nagent:\n  id: reviewer.acme.example\negres:\n  allow: [api.github.com]\n",
			wantErr: "egres",
		},
		{
			name:    "a plausible misspelling of a real field",
			content: "version: v1\nagent:\n  id: reviewer.acme.example\n  credentials: /var/run/secrets/token\n",
			wantErr: "credentials",
		},
		{
			name:    "an ambiguous egress entry",
			content: "version: v1\nagent:\n  id: reviewer.acme.example\negress:\n  allow: [\"api.*.com\"]\n",
			wantErr: "wildcard",
		},
		{
			name:    "not yaml at all",
			content: "\tthis is not yaml\n",
			wantErr: "parsing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadAgentBundle(writeBundle(t, tc.content))
			if err == nil {
				t.Fatalf("LoadAgentBundle accepted %q, want an error", tc.content)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadAgentBundleMissingFile(t *testing.T) {
	if _, err := LoadAgentBundle(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("LoadAgentBundle accepted a missing file, want an error")
	}
}
