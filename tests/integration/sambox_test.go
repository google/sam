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
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/google/sam/internal/sambox"
)

func TestSamBoxNanoInitIntegration(t *testing.T) {
	// Build binaries (specifically we want to verify nano-init builds and runs)
	nanoInitBin := buildBinary(t, "./cmd/nano-init")

	// 1. Setup mock upstream "internet" server representing api.github.com
	var mockServerReceivedAuth string
	mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockServerReceivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("mock-github-response-content"))
	}))
	defer mockServer.Close()

	mockServerURL, err := url.Parse(mockServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse mock server URL: %v", err)
	}

	// 2. Start sam-box in-process on a temporary UDS path
	tempDir := t.TempDir()
	udsPath := filepath.Join(tempDir, "sam-box-test.sock")

	udsListener, err := net.Listen("unix", udsPath)
	if err != nil {
		t.Fatalf("Failed to listen on UDS socket: %v", err)
	}
	defer func() { _ = udsListener.Close() }()

	gatewayTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			if host == "api.github.com" {
				return net.Dial(network, mockServerURL.Host)
			}
			return net.Dial(network, addr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	gateway, err := sambox.NewGateway(nil, gatewayTransport, "")
	if err != nil {
		t.Fatalf("Failed to initialize gateway: %v", err)
	}

	go func() {
		_ = gateway.Serve(udsListener)
	}()

	// 3. Start nano-init routines as a separate process (the target process will be a simple script/agent)
	// We'll configure unprivileged ports for the test
	dnsPort := "10053"

	// Resolve the dynamic C interceptor path
	interceptorPath, err := filepath.Abs("../../bin/libinterceptor.so")
	if err != nil {
		t.Fatalf("Failed to resolve interceptor path: %v", err)
	}

	// Run nano-init wrapper pointing to UDS, spawning curl
	nanoInitCtx, nanoInitCancel := context.WithCancel(context.Background())
	defer nanoInitCancel()

	// Clean up /tmp/ephemeral_ca.pem before running
	_ = os.Remove("/tmp/ephemeral_ca.pem")
	defer func() { _ = os.Remove("/tmp/ephemeral_ca.pem") }()

	nanoInitCmd := exec.CommandContext(nanoInitCtx, nanoInitBin, udsPath,
		"curl", "--cacert", "/tmp/ephemeral_ca.pem", "-s", "https://api.github.com/",
	)
	nanoInitCmd.Env = append(os.Environ(),
		"SAM_DNS_PORT="+dnsPort,
		"SAM_INTERCEPTOR_PATH="+interceptorPath,
	)

	out, err := nanoInitCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nano-init failed: %v\nOutput:\n%s", err, out)
	}

	outStr := string(out)
	t.Logf("Agent Output:\n%s", outStr)

	// 4. Assert that the request reached the mock server and received correct response
	expectedAgentOutput := "mock-github-response-content"
	if !containsString(outStr, expectedAgentOutput) {
		t.Errorf("Expected agent to output %q, got output:\n%s", expectedAgentOutput, outStr)
	}

	if mockServerReceivedAuth != "Bearer mock-token" {
		t.Errorf("Mock server did not receive the expected token: %q", mockServerReceivedAuth)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || containsString(s[1:], substr)))
}
