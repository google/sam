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
	"fmt"
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

// TestSamBoxNanoInitIntegration exercises the real nano-init process end-to-end
// against an in-process sam-box gateway.
//
// nano-init is a container PID-1: it legitimately rewrites /etc/resolv.conf,
// spoofs DNS and rebinds ports. Running it directly on the host would mutate the
// machine (and under `sudo make test` that write actually succeeds and breaks the
// CI runner's DNS). We therefore run it inside a fresh mount + network + UTS
// namespace with a private mount propagation and a bind-mounted /etc/resolv.conf,
// so none of its writes ever reach the real host.
//
// Creating those namespaces (and the bind mount) requires root/CAP_SYS_ADMIN, so
// the test skips when it cannot isolate itself (e.g. a non-root local run).
func TestSamBoxNanoInitIntegration(t *testing.T) {
	if os.Getenv("SAM_TEST_IS_ISOLATED") != "1" {
		if _, err := exec.LookPath("unshare"); err != nil {
			t.Skip("requires the `unshare` binary to isolate nano-init from the host")
		}

		// Compile the binary in the host/parent context where permissions are regular
		nanoInitBin := buildBinary(t, "./cmd/nano-init")

		self, err := os.Executable()
		if err != nil {
			t.Fatalf("Failed to get self executable: %v", err)
		}

		tempFile := filepath.Join(t.TempDir(), "resolv.conf")
		if err := os.WriteFile(tempFile, []byte(""), 0644); err != nil {
			t.Fatalf("Failed to create temp resolv.conf: %v", err)
		}

		bashCmd := fmt.Sprintf(
			"ip link set lo up && mount --bind %s /etc/resolv.conf && %s -test.run=TestSamBoxNanoInitIntegration",
			tempFile,
			self,
		)

		cmd := exec.Command("unshare", "-m", "-n", "-r", "bash", "-c", bashCmd)
		cmd.Env = append(os.Environ(),
			"SAM_TEST_IS_ISOLATED=1",
			"SAM_NANO_INIT_BIN="+nanoInitBin,
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("Re-execution under unshare failed: %v", err)
		}
		return
	}

	if os.Geteuid() != 0 {
		t.Skip("requires root (or mapped root namespace) to create mount/network namespaces and bind-mount /etc/resolv.conf")
	}

	nanoInitBin := os.Getenv("SAM_NANO_INIT_BIN")
	if nanoInitBin == "" {
		t.Fatal("SAM_NANO_INIT_BIN environment variable not set")
	}

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

	interceptorsDir, err := filepath.Abs("../../bin")
	if err != nil {
		t.Fatalf("Failed to resolve interceptor dir: %v", err)
	}
	secretStore := map[string]sambox.SecretConfig{
		"api.github.com": {
			Kind:  sambox.SecretKindBearer,
			Value: "my-github-token-123",
		},
	}
	gateway, err := sambox.NewGateway(secretStore, gatewayTransport, interceptorsDir)
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

	if mockServerReceivedAuth != "Bearer my-github-token-123" {
		t.Errorf("Mock server did not receive the expected token: %q", mockServerReceivedAuth)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || containsString(s[1:], substr)))
}
