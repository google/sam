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

package protocol

import "testing"

func TestExtractBearerFromValues(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		wantErr bool
	}{
		{name: "valid bearer", values: []string{"Bearer token-1"}, wantErr: false},
		{name: "valid among many", values: []string{"Basic abc", "Bearer token-2"}, wantErr: false},
		{name: "missing header", values: nil, wantErr: true},
		{name: "wrong scheme", values: []string{"Basic abc"}, wantErr: true},
		{name: "empty token", values: []string{"Bearer   "}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := extractBearerFromValues(tc.values)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
