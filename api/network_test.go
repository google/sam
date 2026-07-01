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
		{
			name:     "Target with underscore",
			target:   "client_peer_id:value_with_underscore",
			wantType: "client_peer_id",
			wantName: "value_with_underscore",
		},
		{
			name:     "Wildcard fact",
			target:   "*:*",
			wantType: "*",
			wantName: "*",
		},
		{
			name:     "Hierarchical URI with path",
			target:   "mcp://my_service/tool",
			wantType: "mcp",
			wantName: "my_service/tool",
		},
		{
			name:     "Hierarchical URI with underscore",
			target:   "mcp://my_service_name",
			wantType: "mcp",
			wantName: "my_service_name",
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
