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

func TestSamNodeJoin(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	tmpHome := t.TempDir()
	env := append(os.Environ(),
		"HOME="+tmpHome,
		"XDG_CONFIG_HOME="+filepath.Join(tmpHome, ".config"),
	)

	// Mock OIDC server for device flow
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                        "http://" + r.Host,
			"token_endpoint":                "http://" + r.Host + "/token",
			"device_authorization_endpoint": "http://" + r.Host + "/device/code",
		}); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	})
	mux.HandleFunc("/device/code", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               "dev_code_123",
			"user_code":                 "ABCD-1234",
			"verification_uri":          "http://example.com/verify",
			"verification_uri_complete": "http://example.com/verify?code=ABCD-1234",
			"expires_in":                60,
			"interval":                  1,
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
	oidcServer := httptest.NewServer(mux)
	defer oidcServer.Close()

	// Start mock libp2p hub that knows about our mock OIDC server
	_, hubAddr := startMockLibp2pHubWithOIDC(t, oidcServer.URL)

	stdout, stderr, err := runCommand(
		t,
		repoRoot(t),
		5*time.Second,
		env,
		"", // No stdin needed
		nodeBin,
		"join",
		hubAddr,
	)
	if err != nil {
		t.Fatalf("join command failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	out := stdout + stderr
	if !strings.Contains(out, "Successfully joined the Sovereign Agent Mesh!") {
		t.Fatalf("join did not succeed:\n%s", out)
	}

	// Verify that the identity is stored and node can run
	stdout, stderr, err = runCommand(
		t,
		repoRoot(t),
		3*time.Second,
		env,
		"",
		nodeBin,
		"run",
		"--hub", hubAddr,
		"--bind-addr", "127.0.0.1:0",
		"--api-token", "dummy-token",
	)
	if err != context.DeadlineExceeded {
		t.Fatalf("expected run command to keep running, got: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	out = stdout + stderr
	if !strings.Contains(out, "Using stored identity.") {
		t.Fatalf("node did not use stored identity:\n%s", out)
	}
}
