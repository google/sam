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

package hub

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/sam/api"
)

func TestLoadPolicyConfig(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		nonexistent bool
		wantErr     bool
		verify      func(t *testing.T, config *api.PolicyConfig)
	}{
		{
			name: "Valid comprehensive config from docs",
			yamlContent: `
version: "v1alpha1"

# Bindings map OIDC identities (sub/user, email, groups) to SAM Roles.
# Note: Kubernetes projected service account tokens do not carry 'groups' claims,
# so they must be bound explicitly using their 'user' claim format.
bindings:
  # 1. Global Admins (Infrastructure SAs, Lead Architects)
  - members: ["user:system:serviceaccount:sam-mesh:admin-sa"]
    role: "admin"
  - members: ["group:infrastructure-leads"]
    role: "admin"

  # 2. Software Developers
  - members: ["group:software-engineering-team"]
    role: "developer"

  # 3. Data Scientists & AI Engineers
  - members: ["group:data-science-team"]
    role: "data-scientist"

  # 4. Contractors / Read-Only Audits
  - members: ["email:audit-contractor@external.com"]
    role: "auditor"

# Roles define the allowed destinations (allowed_targets) and tools (allowed_services)
roles:
  # Admins have full, unrestricted access to the entire mesh
  admin:
    allowed_targets:
      - "*"
    allowed_services:
      - "*"

  # Developers can call development tools on dev nodes
  developer:
    allowed_targets:
      - "group:dev-nodes"           # Can only call nodes in the 'dev-nodes' target group
    allowed_services:
      - "mcp://code-reviewer"       # Can call the code reviewer tool
      - "mcp://git-helper"          # Can call git helper tools
      - "mcp://build-runner.*"      # Wildcard: matches any build runner sub-service (e.g. build-runner.go)

  # Data Scientists can call database tools and all AI inference endpoints
  data-scientist:
    allowed_targets:
      - "group:data-nodes"          # Can call nodes in the 'data-nodes' target group
      - "node:12D3KooWSpecialNode"  # Can call a specific high-compute node directly
    allowed_services:
      - "mcp://db-reader"           # Can query databases
      - "inference://*"             # Wildcard: can access any LLM inference service

  # Auditors can only query metadata catalogs and cannot call operational tools
  auditor:
    allowed_targets:
      - "*"
    allowed_services:
      - "system://sam.catalog"      # Strictly limited to tool discovery/metadata

`,
			wantErr: false,
		},
		{
			name: "Valid config with exact services",
			yamlContent: `
version: "v1alpha1"
roles:
  data-scientist:
    allowed_targets: ["node:db-agent.data-mesh"]
    allowed_services: ["system://query-database", "mcp://db-agent"]
    custom_datalog:
      - 'department("analytics");'
`,
			wantErr: false,
			verify: func(t *testing.T, config *api.PolicyConfig) {
				if config.Version != "v1alpha1" {
					t.Errorf("expected version v1alpha1, got %s", config.Version)
				}
				role, ok := config.Roles["data-scientist"]
				if !ok {
					t.Fatal("expected role data-scientist to exist")
				}
				if len(role.AllowedTargets) != 1 || role.AllowedTargets[0] != "node:db-agent.data-mesh" {
					t.Errorf("unexpected allowed targets: %v", role.AllowedTargets)
				}
				if len(role.AllowedServices) != 2 || role.AllowedServices[0] != "system://query-database" || role.AllowedServices[1] != "mcp://db-agent" {
					t.Errorf("unexpected allowed services: %v", role.AllowedServices)
				}
				if len(role.CustomDatalog) != 1 || role.CustomDatalog[0] != `department("analytics");` {
					t.Errorf("unexpected custom datalog: %v", role.CustomDatalog)
				}
			},
		},
		{
			name: "Invalid YAML syntax",
			yamlContent: `
version: "v1alpha1"
roles:
  data-scientist:
    allowed_targets: [missing closing bracket
`,
			wantErr: true,
		},
		{
			name:        "Nonexistent file loads empty config",
			nonexistent: true,
			wantErr:     false,
			verify: func(t *testing.T, config *api.PolicyConfig) {
				if config == nil {
					t.Fatal("expected non-nil config for missing file")
				}
				if len(config.Roles) != 0 {
					t.Errorf("expected empty roles, got %d", len(config.Roles))
				}
			},
		},
		{
			name: "Invalid custom datalog fact syntax",
			yamlContent: `
version: "v1alpha1"
roles:
  data-scientist:
    custom_datalog:
      - 'invalid fact syntax'
`,
			wantErr: true,
		},
		{
			name: "Valid group binding",
			yamlContent: `
version: "v1alpha1"
bindings:
  - members: ["group:system:serviceaccounts:sam-canary-bananas"]
    role: "mesh-member"
roles:
  mesh-member:
    allowed_services: ["mcp://1.0.0"]
`,
			wantErr: false,
			verify: func(t *testing.T, config *api.PolicyConfig) {
				if len(config.Bindings) != 1 {
					t.Errorf("expected 1 binding, got %d", len(config.Bindings))
				}
				if len(config.Bindings[0].Members) == 0 || config.Bindings[0].Members[0] != "group:system:serviceaccounts:sam-canary-bananas" || config.Bindings[0].Role != "mesh-member" {
					t.Errorf("unexpected binding values: %+v", config.Bindings[0])
				}
			},
		},
		{
			name: "Invalid binding mapping to nonexistent role",
			yamlContent: `
version: "v1alpha1"
bindings:
  - members: ["group:system:serviceaccounts:sam-canary-bananas"]
    role: "non-existent-role"
roles:
  mesh-member:
    allowed_services: ["mcp://1.0.0"]
`,
			wantErr: true,
		},
		{
			name: "Valid user binding",
			yamlContent: `
version: "v1alpha1"
bindings:
  - members: ["user:system:serviceaccount:sam-canary:sam-node-sa"]
    role: "mesh-member"
roles:
  mesh-member:
    allowed_services: ["mcp://1.0.0"]
`,
			wantErr: false,
			verify: func(t *testing.T, config *api.PolicyConfig) {
				if len(config.Bindings) != 1 {
					t.Errorf("expected 1 binding, got %d", len(config.Bindings))
				}
				if len(config.Bindings[0].Members) == 0 || config.Bindings[0].Members[0] != "user:system:serviceaccount:sam-canary:sam-node-sa" || config.Bindings[0].Role != "mesh-member" {
					t.Errorf("unexpected binding values: %+v", config.Bindings[0])
				}
			},
		},
		{
			name: "Invalid binding with no members",
			yamlContent: `
version: "v1alpha1"
bindings:
  - role: "mesh-member"
roles:
  mesh-member:
    allowed_services: ["mcp://1.0.0"]
`,
			wantErr: true,
		},
		{
			name: "Invalid binding with invalid prefix",
			yamlContent: `
version: "v1alpha1"
bindings:
  - members: ["invalid-prefix:some-user"]
    role: "mesh-member"
roles:
  mesh-member:
    allowed_services: ["mcp://1.0.0"]
`,
			wantErr: true,
		},
		{
			name: "Valid binding with all valid member prefixes",
			yamlContent: `
version: "v1alpha1"
bindings:
  - members: ["user:bob", "group:eng", "email:bob@example.com", "node:12D3KooW", "system:authenticated"]
    role: "mesh-member"
roles:
  mesh-member:
    allowed_services: ["mcp://1.0.0"]
`,
			wantErr: false,
			verify: func(t *testing.T, config *api.PolicyConfig) {
				if len(config.Bindings) != 1 {
					t.Errorf("expected 1 binding, got %d", len(config.Bindings))
				}
				if len(config.Bindings[0].Members) != 5 {
					t.Errorf("expected 5 members, got %d", len(config.Bindings[0].Members))
				}
			},
		},
		{
			name: "Invalid binding missing colon in member string",
			yamlContent: `
version: "v1alpha1"
bindings:
  - members: ["userbob"]
    role: "mesh-member"
roles:
  mesh-member:
    allowed_services: ["mcp://1.0.0"]
`,
			wantErr: true,
		},
		{
			name: "Valid wildcard - global wildcard",
			yamlContent: `
version: "v1alpha1"
roles:
  admin:
    allowed_services: ["*"]
`,
			wantErr: false,
		},
		{
			name: "Valid wildcard - type wildcard",
			yamlContent: `
version: "v1alpha1"
roles:
  admin:
    allowed_services: ["mcp://*"]
`,
			wantErr: false,
		},
		{
			name: "Valid wildcard - domain prefix wildcard",
			yamlContent: `
version: "v1alpha1"
roles:
  admin:
    allowed_services: ["mcp://*.service.local"]
`,
			wantErr: false,
		},
		{
			name: "Valid wildcard - domain suffix wildcard",
			yamlContent: `
version: "v1alpha1"
roles:
  admin:
    allowed_services: ["mcp://service.*"]
`,
			wantErr: false,
		},
		{
			name: "Invalid wildcard - arbitrary partial prefix matching",
			yamlContent: `
version: "v1alpha1"
roles:
  admin:
    allowed_services: ["mcp://dev-*"]
`,
			wantErr: true,
		},
		{
			name: "Invalid wildcard - arbitrary partial suffix matching",
			yamlContent: `
version: "v1alpha1"
roles:
  admin:
    allowed_services: ["mcp://*-prod"]
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
				path = filepath.Join(dir, "policy.yaml")
				if err := os.WriteFile(path, []byte(tt.yamlContent), 0644); err != nil {
					t.Fatalf("failed to write temp policy file: %v", err)
				}
			}

			config, err := LoadPolicyConfig(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("LoadPolicyConfig() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && tt.verify != nil {
				tt.verify(t, config)
			}
		})
	}
}
