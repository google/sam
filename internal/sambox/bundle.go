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
	"fmt"
	"os"

	"gopkg.in/yaml.v2"

	"github.com/google/sam/api"
)

// An agent bundle is what the platform declares about one agent. Its canonical
// home is a file in the agent's own state directory, so that suspending an
// agent on one host and resuming it on another carries it along with no extra
// machinery: the gateway on the new host reads the same bundle and asserts the
// same identity.
//
// Parsing is strict. A bundle is a security document, and a typo in a field
// name that silently parsed as "absent" would hand an agent broader access than
// intended, or an identity nobody granted it.

// AgentBundle is the parsed form of that file.
type AgentBundle struct {
	Version string        `yaml:"version"`
	Agent   AgentIdentity `yaml:"agent"`
	Egress  BundleEgress  `yaml:"egress"`

	// Ingress is what this agent is permitted to serve, not what it is
	// currently serving. The agent says when it is ready, and on which port,
	// through the gateway's ingress endpoint; the platform decides only which
	// names it may claim.
	Ingress []BundleIngress `yaml:"ingress"`

	// egress is the compiled form of Egress.Allow, built during loading so a
	// malformed allowlist fails at startup rather than on an agent's first
	// request.
	egress *EgressPolicy
}

// BundleIngress is one mesh service the agent may advertise.
type BundleIngress struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`
}

// AgentIdentity names the principal the gateway asserts for this sandbox.
type AgentIdentity struct {
	// ID is the canonical mesh identifier, without the "agent:" prefix.
	ID string `yaml:"id"`

	// ExternalID is the platform's own identifier, kept verbatim: the
	// translation into ID is not always reversible, and an auditor needs the
	// value the platform actually issued. When credentials are verified, it is
	// also the subject the credential has to attest.
	ExternalID string `yaml:"external_id"`

	// Credential is the path to the credential the platform issued this
	// workload, such as a projected Kubernetes service-account token. It backs
	// the claim the rest of this file makes; see credential.go.
	Credential string `yaml:"credential"`
}

// BundleEgress is the agent's allowance outside the mesh. Absent means none.
type BundleEgress struct {
	Allow []string `yaml:"allow"`
}

// LoadAgentBundle reads and validates a bundle.
func LoadAgentBundle(path string) (*AgentBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the agent bundle: %w", err)
	}

	var bundle AgentBundle
	// Strict: an unrecognised field is a mistake worth failing on, and it is
	// also how a bundle written for a later version announces itself.
	if err := yaml.UnmarshalStrict(data, &bundle); err != nil {
		return nil, fmt.Errorf("parsing the agent bundle %s: %w", path, err)
	}

	if bundle.Version != BundleVersion {
		return nil, fmt.Errorf("agent bundle %s has version %q, want %q", path, bundle.Version, BundleVersion)
	}
	if err := api.ValidateAgentID(bundle.Agent.ID); err != nil {
		return nil, fmt.Errorf("agent bundle %s: %w", path, err)
	}

	policy, err := NewEgressPolicy(bundle.Egress.Allow)
	if err != nil {
		return nil, fmt.Errorf("agent bundle %s: %w", path, err)
	}
	bundle.egress = policy

	for i, ingress := range bundle.Ingress {
		if _, err := api.ParseServiceType(ingress.Type); err != nil {
			return nil, fmt.Errorf("agent bundle %s: ingress %d: %w", path, i, err)
		}
		if err := api.ValidateServiceFormat(ingress.Type + "://" + ingress.Name); err != nil {
			return nil, fmt.Errorf("agent bundle %s: ingress %d: %w", path, i, err)
		}
	}

	return &bundle, nil
}

// BundleVersion is the only bundle version this gateway understands.
const BundleVersion = "v1"

// EgressPolicy returns the compiled allowlist.
func (b *AgentBundle) EgressPolicy() *EgressPolicy { return b.egress }
