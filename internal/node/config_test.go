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

package node

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/sam/api"
)

func TestLoadNodeConfig(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		nonexistent bool
		wantErr     bool
		verify      func(t *testing.T, config *NodeConfigComplete)
	}{
		{
			name: "Valid comprehensive config from docs",
			yamlContent: `
version: "v1alpha1"

# Static services hosted by this local node
services:
  - type: "mcp"
    name: "db-reader"
    description: "Read-only SQL execution tool"
    target_url: "http://127.0.0.1:5001/mcp"

  - type: "mcp"
    name: "db-writer"
    description: "Database modification tool"
    target_url: "http://127.0.0.1:5002/mcp"

# Local policies further restrict or override permissions on this specific node
attenuation:
  # local rules generate new facts based on existing ones
  rules:
    # e.g., 'is_off_hours() <- current_hour($h), $h >= 21;'

  # local checks must be satisfied for any connection to succeed
  checks:
    # 1. Enforce strict TLS certificate expiry limit
    - 'check if time($time), $time < 2026-12-31T23:59:59Z;'

  # local policies can contain deny rules (to restrict control plane grants) or allow rules (to override implicit denies)
  policies:
    # 2. Block db-writer calls during off-hours (9 PM to 6 AM)
    - 'deny if service("mcp", "db-writer"), current_hour($hour), $hour >= 21;'
    - 'deny if service("mcp", "db-writer"), current_hour($hour), $hour < 6;'
    
    # 3. Restrict contractors from accessing db-writer even if the control plane granted it
    - 'deny if service("mcp", "db-writer"), role("contractor");'
    
    # 4. Explicitly allow local admin bypass
    - 'allow if user("local-admin");'

`,
			wantErr: false,
		},
		{
			name: "Valid config with multiple services and attenuation",
			yamlContent: `
version: "v1alpha1"
attenuation:
  policies:
    - 'deny if user("untrusted_sub_id");'
  checks:
    - 'check if time($time), $time < 2026-12-31T00:00:00Z;'
services:
  - type: "mcp"
    name: "test-mcp"
    description: "Test MCP Service"
    target_url: "http://localhost:8080"
  - type: "inference"
    name: "test-inference"
    description: "Test Inference Service"
    command: ["python3", "-m", "llama"]
    env:
      MODEL_PATH: "/models/llama"
`,
			wantErr: false,
			verify: func(t *testing.T, config *NodeConfigComplete) {
				if len(config.Policies) != 1 {
					t.Errorf("expected 1 policy, got %d", len(config.Policies))
				}
				if len(config.Checks) != 1 {
					t.Errorf("expected 1 check, got %d", len(config.Checks))
				}
				if len(config.Services) != 2 {
					t.Errorf("expected 2 services, got %d", len(config.Services))
				}
				s1 := config.Services[0]
				if s1.Type != "mcp" || s1.Name != "test-mcp" || s1.TargetURL != "http://localhost:8080" {
					t.Errorf("unexpected service 1: %+v", s1)
				}
				s2 := config.Services[1]
				if s2.Type != "inference" || s2.Name != "test-inference" || len(s2.Command) != 3 || s2.Env["MODEL_PATH"] != "/models/llama" {
					t.Errorf("unexpected service 2: %+v", s2)
				}
			},
		},
		{
			name: "Valid service name containing underscores",
			yamlContent: `
version: "v1alpha1"
services:
  - type: "mcp"
    name: "valid_mcp_name"
    target_url: "http://localhost:8080"
`,
			wantErr: false,
			verify: func(t *testing.T, config *NodeConfigComplete) {
				if len(config.Services) != 1 {
					t.Errorf("expected 1 service, got %d", len(config.Services))
				}
				s := config.Services[0]
				if s.Type != "mcp" || s.Name != "valid_mcp_name" || s.TargetURL != "http://localhost:8080" {
					t.Errorf("unexpected service: %+v", s)
				}
			},
		},
		{
			name: "Invalid service name containing invalid DNS characters",
			yamlContent: `
version: "v1alpha1"
services:
  - type: "mcp"
    name: "service@123"
    target_url: "http://localhost:8080"
`,
			wantErr: true,
		},
		{
			name: "Invalid service type empty",
			yamlContent: `
version: "v1alpha1"
services:
  - type: ""
    name: "valid-name"
    target_url: "http://localhost:8080"
`,
			wantErr: true,
		},
		{
			name: "Invalid service name empty",
			yamlContent: `
version: "v1alpha1"
services:
  - type: "mcp"
    name: ""
    target_url: "http://localhost:8080"
`,
			wantErr: true,
		},
		{
			name: "Invalid YAML syntax",
			yamlContent: `
version: "v1alpha1"
services:
  - type: [unclosed list
`,
			wantErr: true,
		},
		{
			name:        "Nonexistent config file returns empty config",
			nonexistent: true,
			wantErr:     false,
			verify: func(t *testing.T, config *NodeConfigComplete) {
				if config == nil {
					t.Fatal("expected non-nil config")
				}
				if len(config.Services) != 0 || len(config.Policies) != 0 || len(config.Checks) != 0 {
					t.Errorf("expected empty config, got: %+v", config)
				}
			},
		},
		{
			name: "Invalid local attenuation policy syntax",
			yamlContent: `
version: "v1alpha1"
attenuation:
  policies:
    - "deny if invalid datalog syntax"
`,
			wantErr: true,
		},
		{
			name: "Invalid local attenuation check syntax",
			yamlContent: `
version: "v1alpha1"
attenuation:
  checks:
    - "check if invalid check syntax"
`,
			wantErr: true,
		},
		{
			name: "Invalid local attenuation rule syntax",
			yamlContent: `
version: "v1alpha1"
attenuation:
  rules:
    - "invalid rule syntax"
`,
			wantErr: true,
		},
		{
			// A node must refuse a schema it cannot read rather than reinterpret it
			// as v1alpha1, which would silently reinterpret its attenuation rules.
			name: "Unsupported future config version",
			yamlContent: `
version: "v2"
services:
  - type: "mcp"
    name: "db-reader"
    target_url: "http://127.0.0.1:5001/mcp"
`,
			wantErr: true,
		},
		{
			name: "Version omitted is read as the original schema",
			yamlContent: `
services:
  - type: "mcp"
    name: "db-reader"
    target_url: "http://127.0.0.1:5001/mcp"
`,
			wantErr: false,
			verify: func(t *testing.T, config *NodeConfigComplete) {
				if len(config.Services) != 1 {
					t.Fatalf("got %d services, want 1", len(config.Services))
				}
			},
		},
		{
			// Dropping an unrecognised key under attenuation would quietly weaken
			// the node, so an unknown key is an error rather than a no-op.
			name: "Unknown key is rejected",
			yamlContent: `
version: "v1alpha1"
attenuation:
  policies:
    - 'deny if user("bob");'
  policiez:
    - 'deny if user("alice");'
`,
			wantErr: true,
		},
		{
			name: "Labels are parsed",
			yamlContent: `
version: "v1alpha1"
labels:
  region: "us-east-1"
  team: "platform"
`,
			wantErr: false,
			verify: func(t *testing.T, config *NodeConfigComplete) {
				if len(config.Labels) != 2 {
					t.Fatalf("got %d labels, want 2: %v", len(config.Labels), config.Labels)
				}
				if config.Labels["region"] != "us-east-1" || config.Labels["team"] != "platform" {
					t.Errorf("unexpected labels: %v", config.Labels)
				}
			},
		},
		{
			// The label set is what the control plane attests, so a malformed
			// one must stop the node at load rather than at enrollment.
			name: "Malformed label key is rejected",
			yamlContent: `
version: "v1alpha1"
labels:
  "bad key!": "us-east-1"
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			if tt.nonexistent {
				path = filepath.Join(t.TempDir(), "nonexistent.yaml")
			} else {
				dir := t.TempDir()
				path = filepath.Join(dir, "sam-node.yaml")
				if err := os.WriteFile(path, []byte(tt.yamlContent), 0644); err != nil {
					t.Fatalf("failed to write temp config file: %v", err)
				}
			}

			config, err := LoadNodeConfig(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("LoadNodeConfig() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && tt.verify != nil {
				tt.verify(t, config)
			}
		})
	}
}

func TestCompleteNodeConfig(t *testing.T) {
	got, err := CompleteNodeConfig(api.NodeConfig{
		Services:    []api.ServiceConfig{{Type: "mcp", Name: "phone-sensors"}},
		Attenuation: api.Attenuation{Checks: []string{`check if label("region", "eu-west-1")`}},
	})
	if err != nil {
		t.Fatalf("CompleteNodeConfig() error = %v", err)
	}
	if len(got.Checks) != 1 || len(got.Services) != 1 {
		t.Fatalf("got %d checks and %d services, want 1 and 1", len(got.Checks), len(got.Services))
	}

	if _, err := CompleteNodeConfig(api.NodeConfig{
		Attenuation: api.Attenuation{Checks: []string{"not datalog"}},
	}); err == nil {
		t.Fatal("CompleteNodeConfig() with invalid Datalog: want error, got nil")
	}
}

func TestLoadNodeConfigEgressFloor(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "sam-node.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("floor is loaded", func(t *testing.T) {
		cfg, err := LoadNodeConfig(write(t, `
version: v1alpha1
egress:
  require_labels:
    jurisdiction: eu
    compliance: gdpr
`))
		if err != nil {
			t.Fatalf("LoadNodeConfig: %v", err)
		}
		if len(cfg.EgressRequireLabels) != 2 ||
			cfg.EgressRequireLabels["jurisdiction"] != "eu" ||
			cfg.EgressRequireLabels["compliance"] != "gdpr" {
			t.Errorf("EgressRequireLabels = %v", cfg.EgressRequireLabels)
		}
	})

	t.Run("absent block means no floor", func(t *testing.T) {
		cfg, err := LoadNodeConfig(write(t, "version: v1alpha1\n"))
		if err != nil {
			t.Fatalf("LoadNodeConfig: %v", err)
		}
		if cfg.EgressRequireLabels != nil {
			t.Errorf("no egress block must leave the floor nil, got %v", cfg.EgressRequireLabels)
		}
	})

	// Rejected at load: a floor that cannot compile would otherwise fail open
	// on the first request that needed it.
	t.Run("a malformed floor fails startup", func(t *testing.T) {
		for _, body := range []string{
			"version: v1alpha1\negress:\n  require_labels:\n    \"bad key!\": eu\n",
			"version: v1alpha1\negress:\n  require_labels:\n    jurisdiction: \"has,comma\"\n",
			"version: v1alpha1\negress:\n  require_labels:\n    jurisdiction: \"\"\n",
		} {
			if _, err := LoadNodeConfig(write(t, body)); err == nil {
				t.Errorf("expected a load error for %q", body)
			}
		}
	})

	// The schema is strict, so a typo in the block name is refused rather than
	// silently leaving the node with no floor.
	t.Run("a misspelled key is refused, not ignored", func(t *testing.T) {
		if _, err := LoadNodeConfig(write(t, "version: v1alpha1\negress:\n  required_labels:\n    jurisdiction: eu\n")); err == nil {
			t.Error("require_labels misspelled as required_labels must fail the strict schema")
		}
	})
}
