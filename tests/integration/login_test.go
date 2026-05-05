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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSamNodeLogin(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	_, hubAddr := startMockHub(t)
	tmpHome := t.TempDir()
	env := append(os.Environ(),
		"HOME="+tmpHome,
		"XDG_CONFIG_HOME="+filepath.Join(tmpHome, ".config"),
	)

	// We simulate the user pasting the token followed by a newline.
	stdin := "test-jwt-token\n"

	stdout, stderr, err := runCommand(
		t,
		repoRoot(t),
		5*time.Second,
		env,
		stdin,
		nodeBin,
		"login",
		"--hub", hubAddr,
		"--token-url", "http://example.com/token",
	)
	if err != nil {
		t.Fatalf("login command failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	out := stdout + stderr
	if !strings.Contains(out, "Login successful and identity stored.") {
		t.Fatalf("login did not succeed:\n%s", out)
	}

	// Verify that the identity is actually stored.
	// We can try to run the node without flags now!
	stdout, stderr, err = runCommand(
		t,
		repoRoot(t),
		3*time.Second,
		env,
		"",
		nodeBin,
		"run",
		"--hub", hubAddr,
	)
	// We expect it to keep running because it uses stored identity.
	if err != context.DeadlineExceeded {
		t.Fatalf("expected run command to keep running, got: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	out = stdout + stderr
	if !strings.Contains(out, "Using stored identity.") {
		t.Fatalf("node did not use stored identity:\n%s", out)
	}
}
