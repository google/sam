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

// PolicyConfig is the root authorization configuration for the SAM Hub.
type PolicyConfig struct {
	Version  string                `yaml:"version"`
	Bindings []Binding             `yaml:"bindings"`
	Roles    map[string]RolePolicy `yaml:"roles"`
}

type Binding struct {
	Group string `yaml:"group,omitempty"`
	User  string `yaml:"user,omitempty"`
	Email string `yaml:"email,omitempty"`
	Role  string `yaml:"role"`
}

// RolePolicy defines the capabilities granted to a specific authorization role.
//
// AllowedTargets restricts the logical endpoints a peer can route connections to.
// Targets act similarly to Active Directory network groups and must be specified
// using the format of the resolved Biscuit facts. IP address ranges are NOT allowed.
// Valid examples:
//   - "group:backend-nodes"
//   - "user:admin@example.com"
//   - "role:developer"
//   - "node:12D3KooW..."
//
// AllowedServices defines the application-level services a peer can invoke.
// Services are prefixed by their protocol/type to permit fine-grained scoping.
// Wildcards are supported (e.g., "mcp:*").
// Valid examples:
//   - "mcp:local-shell-tools"
//   - "inference:openrouter"
//   - "system:query_db"
type RolePolicy struct {
	AllowedTargets  []string `yaml:"allowed_targets,omitempty"`
	AllowedServices []string `yaml:"allowed_services,omitempty"`
	CustomDatalog   []string `yaml:"custom_datalog,omitempty"`
}

type ServiceConfig struct {
	Type        string            `yaml:"type"` // e.g., "mcp", "inference"
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	TargetURL   string            `yaml:"target_url,omitempty"`
	Command     []string          `yaml:"command,omitempty"`
	Env         map[string]string `yaml:"env,omitempty"`
}

// NodeConfig defines the optional attenuation rules and static services for a specific SAM Node.
type NodeConfig struct {
	Version     string          `yaml:"version"`
	Attenuation Attenuation     `yaml:"attenuation"`
	Services    []ServiceConfig `yaml:"services"`
}

type Attenuation struct {
	Policies []string `yaml:"policies"`
	Checks   []string `yaml:"checks"`
	Rules    []string `yaml:"rules"`
}
