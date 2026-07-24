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

const (
	// SystemAuthenticated is a special member string representing any authenticated user.
	SystemAuthenticated = "sam:system:authenticated"
)

var (
	// ValidMemberPrefixes defines the allowed identity prefixes in policy configuration.
	ValidMemberPrefixes = map[string]struct{}{
		FactUser:  {},
		FactGroup: {},
		FactEmail: {},
		FactNode:  {},
	}
)

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
