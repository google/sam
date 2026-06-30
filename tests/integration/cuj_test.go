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

func TestSamNodeRunWithManualTokenStarts(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	_, hubAddr := startMockLibp2pHub(t)
	tmpHome := t.TempDir()
	env := append(os.Environ(),
		"HOME="+tmpHome,
		"XDG_CONFIG_HOME="+filepath.Join(tmpHome, ".config"),
	)

	stdout, stderr, err := runCommand(
		t,
		repoRoot(t),
		3*time.Second,
		env,
		"",
		nodeBin,
		"run", "--hub", hubAddr,
		"--jwt", "test-jwt",
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--bind-addr", "127.0.0.1:0",
		"--api-token", "dummy-token",
	)
	if err != context.DeadlineExceeded {
		t.Fatalf("expected run command to keep running until timeout, got: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	out := stdout + stderr
	if !strings.Contains(out, "SAM Node Online") {
		t.Fatalf("node did not reach online state:\n%s", out)
	}
}
