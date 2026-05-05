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
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	// Mock OIDC server for device flow
	mux := http.NewServeMux()
	mux.HandleFunc("/device/code", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":      "dev_code_123",
			"user_code":        "ABCD-1234",
			"verification_uri": "http://example.com/verify",
			"expires_in":       60,
			"interval":         1,
		}); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{
			"access_token": "test-jwt-token",
			"id_token":     "test-jwt-token",
		}); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	stdout, stderr, err := runCommand(
		t,
		repoRoot(t),
		5*time.Second,
		env,
		"", // No stdin needed
		nodeBin,
		"login",
		"--hub", hubAddr,
		"--token-url", server.URL+"/token",
		"--device-auth-url", server.URL+"/device/code",
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
