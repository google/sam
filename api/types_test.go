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
	"reflect"
	"testing"
)

func TestParseServiceTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantType string
		wantName string
	}{
		{
			name:     "Global wildcard",
			target:   "*",
			wantType: "*",
			wantName: "*",
		},
		{
			name:     "Explicit type and name",
			target:   "mcp:db-agent",
			wantType: "mcp",
			wantName: "db-agent",
		},
		{
			name:     "Type wildcard",
			target:   "mcp:*",
			wantType: "mcp",
			wantName: "*",
		},
		{
			name:     "System fallback (no colon)",
			target:   "catalog",
			wantType: "",
			wantName: "catalog",
		},
		{
			name:     "Empty string",
			target:   "",
			wantType: "",
			wantName: "",
		},
		{
			name:     "Multiple colons",
			target:   "mcp:tool:subtool",
			wantType: "mcp",
			wantName: "tool:subtool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotName := ParseServiceTarget(tt.target)
			if gotType != tt.wantType {
				t.Errorf("ParseServiceTarget() gotType = %v, want %v", gotType, tt.wantType)
			}
			if gotName != tt.wantName {
				t.Errorf("ParseServiceTarget() gotName = %v, want %v", gotName, tt.wantName)
			}
		})
	}
}

func TestOIDCClaimToFact(t *testing.T) {
	facts := OIDCClaimToFact()

	want := map[string]string{
		"sub":    FactUser,
		"email":  FactEmail,
		"groups": FactGroup,
	}

	if !reflect.DeepEqual(facts, want) {
		t.Errorf("OIDCClaimToFact() = %v, want %v", facts, want)
	}

	// Verify that modifying the returned map does not mutate the internal map.
	facts["new_claim"] = "new_fact"
	facts2 := OIDCClaimToFact()

	if _, ok := facts2["new_claim"]; ok {
		t.Errorf("OIDCClaimToFact() returned map is not a clone, modifications affect internal state")
	}
}
