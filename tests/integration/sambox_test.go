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
	"strings"
	"testing"
	"time"

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
	if os.Geteuid() != 0 {
		t.Skip("requires root to create mount/network namespaces and bind-mount /etc/resolv.conf")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("requires the `unshare` binary to isolate nano-init from the host")
	}

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

	// 2. Start sam-box in-process on a UDS. The UDS and the bind-mount source for
	// /etc/resolv.conf live outside /tmp so they stay visible after nano-init
	// overlays a fresh tmpfs on /tmp inside its namespace. runDir lives under the
	// test package dir and is removed on cleanup.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	runDir, err := os.MkdirTemp(wd, "sambox-ns-")
	if err != nil {
		t.Fatalf("Failed to create run directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(runDir) }()

	// Copy nano-init into runDir. buildBinary places it under /tmp (t.TempDir),
	// which nano-init's fresh tmpfs-on-/tmp would otherwise hide from exec.
	nanoInitLocal := filepath.Join(runDir, "nano-init")
	if data, err := os.ReadFile(nanoInitBin); err != nil {
		t.Fatalf("Failed to read nano-init binary: %v", err)
	} else if err := os.WriteFile(nanoInitLocal, data, 0755); err != nil {
		t.Fatalf("Failed to stage nano-init binary: %v", err)
	}

	udsPath := filepath.Join(runDir, "sam-box-test.sock")

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

	// The bind-mount source for /etc/resolv.conf. nano-init overwrites
	// /etc/resolv.conf inside its mount namespace; the write lands here instead of
	// on the host's resolv.conf.
	resolvSrc := filepath.Join(runDir, "resolv.conf")
	if err := os.WriteFile(resolvSrc, []byte("nameserver 127.0.0.1\n"), 0644); err != nil {
		t.Fatalf("Failed to seed resolv.conf source: %v", err)
	}

	// 3. Run nano-init (which spawns curl) inside an isolated namespace.
	dnsPort := "10053"

	// Resolve the dynamic C interceptor path (optional; the gateway 404s the
	// bootstrap so nano-init just runs without transparent interception).
	interceptorPath, err := filepath.Abs("../../bin/libinterceptor.so")
	if err != nil {
		t.Fatalf("Failed to resolve interceptor path: %v", err)
	}

	// A hard timeout guarantees the test can never hang the suite waiting on the
	// nano-init/curl subprocess.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Wrapper executed as the namespace's first process: overlay tmpfs on /tmp so
	// nano-init's cert/interceptor writes stay isolated, bind our resolv.conf over
	// /etc/resolv.conf, bring loopback up (a fresh net namespace starts with lo
	// down), then exec nano-init with its arguments.
	const nsSetup = `set -e
mount -t tmpfs tmpfs /tmp
mount --bind "$RESOLV_SRC" /etc/resolv.conf
ip link set lo up
exec "$@"`

	nanoInitCmd := exec.CommandContext(ctx, "unshare",
		"--mount", "--uts", "--net", "--propagation", "private", "--",
		"/bin/sh", "-c", nsSetup, "sh",
		nanoInitLocal, udsPath,
		"curl", "--cacert", "/tmp/ephemeral_ca.pem", "-s", "https://api.github.com/",
	)
	nanoInitCmd.Env = append(os.Environ(),
		"SAM_DNS_PORT="+dnsPort,
		"SAM_INTERCEPTOR_PATH="+interceptorPath,
		"RESOLV_SRC="+resolvSrc,
	)

	out, err := nanoInitCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nano-init failed: %v\nOutput:\n%s", err, out)
	}

	outStr := string(out)
	t.Logf("Agent Output:\n%s", outStr)

	// 4. Assert that the request reached the mock server and received correct response
	expectedAgentOutput := "mock-github-response-content"
	if !strings.Contains(outStr, expectedAgentOutput) {
		t.Errorf("Expected agent to output %q, got output:\n%s", expectedAgentOutput, outStr)
	}

	if mockServerReceivedAuth != "Bearer mock-token" {
		t.Errorf("Mock server did not receive the expected token: %q", mockServerReceivedAuth)
	}
}
