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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSamNodeRunWithoutIdentity(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	tmpHome := t.TempDir()
	env := []string{
		"HOME=" + tmpHome,
		"XDG_CONFIG_HOME=" + filepath.Join(tmpHome, ".config"),
	}
	stdout, stderr, err := runCommand(t, repoRoot(t), 10*time.Second, append(os.Environ(), env...), "", nodeBin, "run")
	if err == nil {
		t.Fatalf("expected sam-node run without identity to fail, but it succeeded\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	out := stdout + stderr
	if !strings.Contains(out, "No JWT or stored identity found") {
		t.Fatalf("expected missing identity message, got:\n%s", out)
	}
}
