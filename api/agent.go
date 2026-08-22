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

import (
	"fmt"
	"strings"
)

// ============================================================================
// Agent Principals
// ============================================================================
//
// An agent is a mesh principal in its own right: policy is written about the
// agent, not about whichever node happens to be hosting it, and the identifier
// survives an agent being suspended on one host and resumed on another.
//
// Agent identifiers are a SAM convention, the way "user", "email" and "group"
// facts are. External identity systems are not expected to adopt it; a
// connector translates into it at admission, exactly as translateClaimsToFacts
// translates OIDC claims at node enrollment. That translation must be total,
// injective (or tenants collide), hierarchy-preserving (or wildcard policy
// stops being expressible and operators are forced back to enumeration), and
// auditable.
//
//	spiffe://acme.example/prod/reviewer-7  ->  agent:reviewer-7.prod.acme.example
//
// The dotted, most-specific-first shape is not cosmetic. BuildTargetDatalogFact
// compiles "*.acme.example" into a suffix fact that keeps the leading dot and
// "acme.*" into a prefix fact that keeps the trailing dot, so wildcards are
// already anchored on label boundaries: "evil-acme.example" cannot match
// "*.acme.example". A slash-separated identifier would need new fact kinds and
// new matching code, and would reintroduce the boundary bug this avoids.

const (
	// MaxAgentIDLen bounds an agent identifier, matching the DNS name limit it
	// is shaped after.
	MaxAgentIDLen = 253

	// MaxAgentLabelLen bounds one dot-separated label of an agent identifier.
	MaxAgentLabelLen = 63
)

// ValidateAgentID checks an agent identifier: the value part of an "agent:"
// member or target, without the prefix.
//
// The rules exist to keep prefix and suffix policy safe and unambiguous:
// lowercase because the shape is DNS-shaped and DNS is case-insensitive, so
// two identifiers differing only in case must not be two principals; at least
// two labels because the rightmost labels are the authority that keeps
// identifiers from colliding across tenants; and no wildcards, because a
// wildcard is a policy pattern and never an identity.
func ValidateAgentID(id string) error {
	if id == "" {
		return fmt.Errorf("agent id cannot be empty")
	}
	if len(id) > MaxAgentIDLen {
		return fmt.Errorf("agent id %q exceeds %d characters", id, MaxAgentIDLen)
	}
	if id != strings.ToLower(id) {
		return fmt.Errorf("agent id %q must be lowercase", id)
	}
	if strings.ContainsAny(id, "*:/ ") {
		return fmt.Errorf("agent id %q must not contain a wildcard, a scheme separator, a path or a space", id)
	}

	labels := strings.Split(id, ".")
	if len(labels) < 2 {
		return fmt.Errorf("agent id %q must be qualified by an authority, e.g. reviewer-7.prod.acme.example", id)
	}
	for _, label := range labels {
		if err := validateAgentLabel(label); err != nil {
			return fmt.Errorf("agent id %q: %w", id, err)
		}
	}
	return nil
}

// validateAgentLabel applies the same character rules as dnsNameRegex uses for
// service names, so an agent identifier and a service name are validated alike.
func validateAgentLabel(label string) error {
	if label == "" {
		return fmt.Errorf("empty label")
	}
	if len(label) > MaxAgentLabelLen {
		return fmt.Errorf("label %q exceeds %d characters", label, MaxAgentLabelLen)
	}
	for i, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
		case r == '-' && i > 0:
		default:
			return fmt.Errorf("label %q contains an invalid character %q", label, r)
		}
	}
	return nil
}

// AgentMember renders an agent identifier as a policy member or target, the
// form used in allowed_targets and role bindings.
func AgentMember(id string) (string, error) {
	if err := ValidateAgentID(id); err != nil {
		return "", err
	}
	return FactAgent + ":" + id, nil
}
