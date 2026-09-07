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
)

func TestValidateLabelKey(t *testing.T) {
	valid := []string{"region", "team", "cloud-region", "on_prem.zone", "A1"}
	for _, k := range valid {
		if err := ValidateLabelKey(k); err != nil {
			t.Errorf("ValidateLabelKey(%q): unexpected error: %v", k, err)
		}
	}

	invalid := []string{"", "has space", "has,comma", "has=equals", strings.Repeat("a", 64)}
	for _, k := range invalid {
		if err := ValidateLabelKey(k); err == nil {
			t.Errorf("ValidateLabelKey(%q): expected error, got nil", k)
		}
	}
}

func TestValidateLabelValue(t *testing.T) {
	valid := []string{"us-east-1", "EU-DE", "office-berlin", "rack.3", "123"}
	for _, v := range valid {
		if err := ValidateLabelValue(v); err != nil {
			t.Errorf("ValidateLabelValue(%q): unexpected error: %v", v, err)
		}
	}

	invalid := []string{"", "has,comma", "has=equals", "has\ttab", strings.Repeat("a", maxLabelValueLen+1)}
	for _, v := range invalid {
		if err := ValidateLabelValue(v); err == nil {
			t.Errorf("ValidateLabelValue(%q): expected error, got nil", v)
		}
	}
}

func TestValidateLabels(t *testing.T) {
	if err := ValidateLabels(nil); err != nil {
		t.Errorf("ValidateLabels(nil): unexpected error: %v", err)
	}
	if err := ValidateLabels(map[string]string{"region": "us-east-1", "team": "platform"}); err != nil {
		t.Errorf("ValidateLabels(valid): unexpected error: %v", err)
	}
	if err := ValidateLabels(map[string]string{"region": ""}); err == nil {
		t.Error("ValidateLabels(empty value): expected error, got nil")
	}
	if err := ValidateLabels(map[string]string{"bad key!": "v"}); err == nil {
		t.Error("ValidateLabels(bad key): expected error, got nil")
	}
}

// TestValidateLabels_ReportsFirstErrorDeterministically guards against
// non-deterministic map iteration: the first reported error must always come
// from the lexicographically smallest invalid key, regardless of iteration
// order. Regression test for the prior bug where ValidateLabels iterated
// the input map directly and returned whatever bad key Go visited first.
func TestValidateLabels_ReportsFirstErrorDeterministically(t *testing.T) {
	bad := map[string]string{
		"region": "v",
		"team":   "v",
		"zulu":   "v",
		"b_ bad": "v",
		"c,key":  "v",
		"a!key":  "v",
	}
	// Repeat the call many times. With deterministic ordering the reported
	// key is always the same (the lexicographically smallest invalid one,
	// here "a!key"; whitespace, comma, and bang are all disallowed by
	// labelKeySyntax, but "a!key" < "b_ bad" < "c,key" lexicographically).
	// With the previous nondeterministic ordering the reported key varied
	// between runs and could be any of "a!key", "b_ bad", or "c,key".
	const iterations = 200
	for i := 0; i < iterations; i++ {
		err := ValidateLabels(bad)
		if err == nil {
			t.Fatalf("iteration %d: expected error, got nil", i)
		}
		if !strings.Contains(err.Error(), `"a!key"`) {
			t.Fatalf("iteration %d: expected error to mention the lexicographically smallest invalid key \"a!key\", got: %v", i, err)
		}
	}
}

// TestValidateLabels_AllKeysValidStaysSorted asserts the happy path still
// accepts sets whose keys happen to be in any order — sorting must not
// introduce a false positive on otherwise valid input.
func TestValidateLabels_AllKeysValidStaysSorted(t *testing.T) {
	labels := map[string]string{"zeta": "1", "alpha": "2", "mike": "3"}
	if err := ValidateLabels(labels); err != nil {
		t.Errorf("ValidateLabels(sorted happy path): unexpected error: %v", err)
	}
}

func TestParseLabels(t *testing.T) {
	labels, err := ParseLabels("region=eu-west-1, team = platform")
	if err != nil {
		t.Fatalf("ParseLabels failed: %v", err)
	}
	if labels["region"] != "eu-west-1" || labels["team"] != "platform" {
		t.Fatalf("unexpected labels: %v", labels)
	}
	if labels, err := ParseLabels(""); err != nil || labels != nil {
		t.Fatalf("empty string should yield no labels, got %v, %v", labels, err)
	}
	if _, err := ParseLabels("no-equals"); err == nil {
		t.Fatal("expected error for label without =")
	}
	if _, err := ParseLabels("k=a,k=b"); err == nil {
		t.Fatal("expected error for duplicate key")
	}
}
