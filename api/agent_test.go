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
	"strings"
	"testing"

	"github.com/biscuit-auth/biscuit-go/v2"
)

func TestValidateAgentID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"fully qualified", "reviewer-7.prod.acme.example", false},
		{"two labels", "reviewer.acme", false},
		{"digits and underscores", "actor_1.ns0.acme.example", false},
		{"substrate actor host", "my-counter-1.demo.actors.resources.substrate.ate.dev", false},

		{"empty", "", true},
		{"single label has no authority", "reviewer", true},
		{"uppercase", "Reviewer.acme.example", true},
		{"wildcard is a pattern not an identity", "*.prod.acme.example", true},
		{"trailing wildcard", "acme.*", true},
		{"carries the prefix", "agent:reviewer.acme.example", true},
		{"contains a path", "acme.example/reviewer", true},
		{"contains a space", "reviewer 7.acme.example", true},
		{"empty label", "reviewer..acme", true},
		{"leading dot", ".acme.example", true},
		{"trailing dot", "reviewer.acme.", true},
		{"label starts with a hyphen", "-reviewer.acme.example", true},
		{"label too long", strings.Repeat("a", 64) + ".acme", true},
		{"id too long", strings.Repeat("a.", 130) + "acme", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAgentID(tc.id)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateAgentID(%q) = nil, want error", tc.id)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateAgentID(%q) returned error: %v", tc.id, err)
			}
		})
	}
}

func TestAgentMember(t *testing.T) {
	got, err := AgentMember("reviewer-7.prod.acme.example")
	if err != nil {
		t.Fatalf("AgentMember returned error: %v", err)
	}
	if want := "agent:reviewer-7.prod.acme.example"; got != want {
		t.Fatalf("AgentMember = %q, want %q", got, want)
	}

	if _, err := AgentMember("*.prod.acme.example"); err == nil {
		t.Fatal("AgentMember accepted a wildcard, want error")
	}
}

// TestAgentPolicyPatternsAreLabelAnchored is the reason agent identifiers are
// dot-separated: the existing target vocabulary compiles wildcards into facts
// that keep the anchoring dot, so a lookalike authority cannot match.
func TestAgentPolicyPatternsAreLabelAnchored(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		wantFact  string
		wantValue string
	}{
		{"suffix keeps the leading dot", "agent:*.prod.acme.example", FactGrantedTargetSuffix, ".prod.acme.example"},
		{"prefix keeps the trailing dot", "agent:acme.*", FactGrantedTargetPrefix, "acme."},
		{"exact", "agent:reviewer-7.prod.acme.example", FactGrantedTargetExact, "reviewer-7.prod.acme.example"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fact := BuildTargetDatalogFact(tc.pattern)
			if fact.Name != tc.wantFact {
				t.Fatalf("BuildTargetDatalogFact(%q) produced %q, want %q", tc.pattern, fact.Name, tc.wantFact)
			}
			if len(fact.IDs) != 2 {
				t.Fatalf("BuildTargetDatalogFact(%q) produced %d terms, want 2", tc.pattern, len(fact.IDs))
			}
			gotFactName, ok := fact.IDs[0].(biscuit.String)
			if !ok || string(gotFactName) != FactAgent {
				t.Errorf("BuildTargetDatalogFact(%q) targets %v, want %q", tc.pattern, fact.IDs[0], FactAgent)
			}
			gotValue, ok := fact.IDs[1].(biscuit.String)
			if !ok || string(gotValue) != tc.wantValue {
				t.Errorf("BuildTargetDatalogFact(%q) value = %v, want %q", tc.pattern, fact.IDs[1], tc.wantValue)
			}
		})
	}
}
