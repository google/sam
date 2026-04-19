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

package db

import (
	"testing"
)

type v2Record struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
}

func TestJSONCodecLazyMigrationV1ToV2(t *testing.T) {
	legacy := []byte(`{"metadata":{"version":1,"updated_at":"2026-01-01T00:00:00Z"},"payload":{"name":"alice"}}`)
	codec := JSONCodec{}

	var out v2Record
	err := codec.Unmarshal(legacy, 2, &out, func(payload map[string]any, fromVersion int) map[string]any {
		if fromVersion < 2 {
			if _, ok := payload["scope"]; !ok {
				payload["scope"] = "default"
			}
		}
		return payload
	})
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if out.Name != "alice" {
		t.Fatalf("Name = %q, want %q", out.Name, "alice")
	}
	if out.Scope != "default" {
		t.Fatalf("Scope = %q, want %q", out.Scope, "default")
	}
}
