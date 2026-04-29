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

package main

import (
	"os"
	"testing"
)

func TestStorePolicies(t *testing.T) {
	dir, err := os.MkdirTemp("", "store-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(dir)
	}()

	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = store.Close()
	}()

	policies := []string{"allow if operation($op)", "deny if user(bad)"}

	if err := store.SavePolicies(policies); err != nil {
		t.Fatalf("failed to save policies: %v", err)
	}

	loaded, err := store.LoadPolicies()
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	if len(loaded) != len(policies) {
		t.Fatalf("expected %d policies, got %d", len(policies), len(loaded))
	}

	for i, p := range policies {
		if loaded[i] != p {
			t.Errorf("expected policy %s, got %s", p, loaded[i])
		}
	}
}
