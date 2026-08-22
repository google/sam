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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/sam/internal/sambox"
)

// TestSandboxCreatesItsOwnNamespaces covers the Kubernetes profile, which is
// the one no runtime isolates.
//
// The other two profiles are handed a network namespace with nowhere to go:
// `docker run --network none` makes one, and a microVM has its own kernel. A
// pod makes neither -- every container in a pod shares one network namespace,
// and the resolv.conf the kubelet writes is shared with them too -- so
// nano-init has to build both for itself.
//
// This runs it the way a pod would: from a namespace that has real interfaces
// and a real resolv.conf, with no external unshare and no privileges. What is
// being asserted is that the agent ends up somewhere else entirely, and that
// the boundary still reaches it there.
//
// It needs /dev/net/tun and unprivileged user namespaces, and skips without
// them rather than passing quietly.
func TestSandboxCreatesItsOwnNamespaces(t *testing.T) {
	const (
		allowedHost = "allowed.example"
		blockedHost = "blocked.example"
		serverBody  = "reached the far side"
	)

	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("this profile needs /dev/net/tun, the same as a pod does: %v", err)
	}

	nanoInitBin := buildBinary(t, "./cmd/nano-init")

	// The namespace this test runs in is emphatically not a sandbox, which is
	// the point: it stands in for the pod's shared namespace. If nano-init
	// used it, the assertions below would fail rather than quietly pass.
	if !hasForeignInterfaces(t) {
		t.Skip("this namespace has no interfaces, so it cannot stand in for a pod's")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, serverBody)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parsing the server URL: %v", err)
	}

	sockDir, err := os.MkdirTemp("", "podsandbox")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer func() { _ = os.RemoveAll(sockDir) }()
	agentSocket := filepath.Join(sockDir, "agent.sock")

	var dialed struct {
		sync.Mutex
		names []string
	}

	egress, err := sambox.NewEgressPolicy([]string{allowedHost})
	if err != nil {
		t.Fatalf("NewEgressPolicy: %v", err)
	}
	listener, err := sambox.ListenSandboxSocket(agentSocket)
	if err != nil {
		t.Fatalf("ListenSandboxSocket: %v", err)
	}

	boundary := &sambox.SOCKS5Server{
		Dialer: &sambox.AgentDialer{
			Router: &sambox.Router{Egress: egress},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					host = address
				}
				dialed.Lock()
				dialed.names = append(dialed.names, host)
				dialed.Unlock()
				return (&net.Dialer{}).DialContext(ctx, network, serverURL.Host)
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		if err := boundary.Serve(ctx, listener); err != nil {
			t.Errorf("boundary: %v", err)
		}
	}()
	defer func() {
		cancel()
		<-served
	}()

	// The agent reports what it can see before using it, so a failure says
	// whether the namespace was wrong or the datapath was.
	agent := fmt.Sprintf(
		`echo "links=$(ip -o link show | cut -d: -f2 | tr -d " " | paste -sd,)"; `+
			`echo "resolv=$(cat /etc/resolv.conf)"; `+
			`curl -sS --max-time 20 http://%s/; echo "allowed-exit=$?"; `+
			`curl -sS --max-time 20 http://%s/; echo "blocked-exit=$?"`,
		allowedHost, blockedHost,
	)

	runCtx, runCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer runCancel()

	out, err := exec.CommandContext(runCtx, nanoInitBin,
		"run", "--create-namespaces", agentSocket, "bash", "-c", agent).CombinedOutput()
	t.Logf("nano-init exited with %v, sandbox output:\n%s", err, out)

	got := string(out)
	if strings.Contains(got, "user namespaces are disabled") ||
		strings.Contains(got, "unprivileged user namespaces are disabled") {
		t.Skipf("this host does not allow the namespaces a pod profile needs:\n%s", got)
	}

	// The whole claim. A pod's namespace has eth0 and whatever else the CNI
	// left; the agent must be somewhere with neither.
	if !strings.Contains(got, "links=lo,tun0") {
		t.Errorf("the agent did not get a namespace of its own; it reported:\n%s", got)
	}
	if !strings.Contains(got, "resolv=nameserver 169.254.1.1") {
		t.Errorf("the agent kept the outer resolv.conf, so a pod's DNS would have been repointed:\n%s", got)
	}

	// And the boundary still reaches it, which is what makes the isolation
	// useful rather than merely complete.
	if !strings.Contains(got, serverBody) || !strings.Contains(got, "allowed-exit=0") {
		t.Errorf("the sandbox did not reach %s through the boundary", allowedHost)
	}
	if strings.Contains(got, "blocked-exit=0") {
		t.Errorf("reaching %s succeeded, want the boundary to refuse it", blockedHost)
	}

	dialed.Lock()
	defer dialed.Unlock()
	if len(dialed.names) != 1 || dialed.names[0] != allowedHost {
		t.Errorf("the boundary dialled %q, want exactly [%q]", dialed.names, allowedHost)
	}
}

// hasForeignInterfaces reports whether this namespace has anything but
// loopback, which is what makes it a stand-in for a pod's.
func hasForeignInterfaces(t *testing.T) bool {
	t.Helper()
	links, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	for _, l := range links {
		if l.Name != "lo" {
			return true
		}
	}
	return false
}
