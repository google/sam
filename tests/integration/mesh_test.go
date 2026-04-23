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

package integration_test

import (
	"strings"
	"testing"
	"time"
)

func TestSamHubHelp(t *testing.T) {
	hubBin := buildBinary(t, "./cmd/sam-hub")
	stdout, stderr, err := runCommand(t, repoRoot(t), 10*time.Second, nil, "", hubBin, "--help")
	if err != nil {
		t.Fatalf("sam-hub --help failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	out := stdout + stderr
	if !strings.Contains(out, "Sovereign Agent Mesh - Multi-Transport Hub") {
		t.Fatalf("unexpected help output:\n%s", out)
	}
}
