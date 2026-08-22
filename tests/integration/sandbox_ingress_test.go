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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/sam/internal/sambox"
)

// TestSandboxServesThroughTheReverseChannel covers the hop that the rest of the
// ingress tests replace.
//
// Those tests set AgentAddr to a server of their own, which exercises the
// declaration, the policy check and the forwarding logic but skips the only
// part that depends on where the agent actually is. In every sandbox profile
// the agent has a network namespace of its own, so the gateway's 127.0.0.1 is
// its own loopback: dialling the agent directly reaches nothing, and no test
// noticed because no test dialled.
//
// Here nano-init builds a real sandbox, the agent listens inside it, and the
// gateway reaches it the only way it can -- over a Unix socket that nano-init
// serves from inside the namespace, because a pathname socket is a filesystem
// object and network namespaces do not apply to it.
func TestSandboxServesThroughTheReverseChannel(t *testing.T) {
	const served = "the agent answered from inside its sandbox"

	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("a sandbox needs /dev/net/tun: %v", err)
	}
	nanoInitBin := buildBinary(t, "./cmd/nano-init")

	sockDir, err := os.MkdirTemp("", "ingress")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer func() { _ = os.RemoveAll(sockDir) }()

	boundarySocket := filepath.Join(sockDir, "agent.sock")
	ingressSocket := filepath.Join(sockDir, "ingress.sock")

	// The sandbox needs a boundary to exist before it will start, though this
	// test never sends anything out through it.
	boundary, err := sambox.ListenSandboxSocket(boundarySocket)
	if err != nil {
		t.Fatalf("ListenSandboxSocket: %v", err)
	}
	defer func() { _ = boundary.Close() }()

	// A port inside the sandbox, which is a different 127.0.0.1 from this
	// process's and is the whole point of the exercise.
	const agentPort = 18080
	agent := fmt.Sprintf(
		`while true; do printf 'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' | nc -l -p %d; done`,
		len(served), served, agentPort)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sandbox := exec.CommandContext(ctx, nanoInitBin, "run",
		"--create-namespaces", "--ingress-socket", ingressSocket,
		boundarySocket, "sh", "-c", agent)
	// One writer, two streams: exec copies stdout and stderr on separate
	// goroutines, so the sink has to tolerate both.
	out := &lockedBuilder{}
	sandbox.Stdout, sandbox.Stderr = out, out
	if err := sandbox.Start(); err != nil {
		t.Fatalf("start the sandbox: %v", err)
	}
	defer func() {
		_ = sandbox.Process.Kill()
		_, _ = sandbox.Process.Wait()
	}()

	// The reverse channel appears once the sandbox is up.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ingressSocket); err == nil {
			break
		}
		if strings.Contains(out.String(), "user namespaces are disabled") {
			t.Skipf("this host does not allow the namespaces a sandbox needs:\n%s", out.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	if _, err := os.Stat(ingressSocket); err != nil {
		t.Fatalf("the sandbox never served its ingress socket: %v\n%s", err, out.String())
	}

	// What the gateway used to do, and what every ingress test still simulates
	// by supplying an address of its own. The agent is listening on this port,
	// but in a namespace this process cannot see, so the dial must fail --
	// otherwise the reverse channel below would be proving nothing.
	direct, err := net.DialTimeout("tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(agentPort)), 2*time.Second)
	if err == nil {
		_ = direct.Close()
		t.Fatalf("dialling 127.0.0.1:%d from outside reached something: the sandbox is not isolated, "+
			"so this test cannot show that the reverse channel is what carries ingress", agentPort)
	}

	// Exactly how the gateway is configured in a pod: it knows the socket, not
	// the agent's whereabouts.
	manager := &sambox.IngressManager{AgentSocket: ingressSocket}
	client := &http.Client{Transport: managerTransport(t, manager)}

	var resp *http.Response
	for time.Now().Before(deadline) {
		// Each attempt is bounded on its own. Sharing the outer deadline meant
		// one attempt that hung -- against a listener the sandbox had not
		// restarted yet -- spent the whole budget and failed the test under
		// load, while passing whenever it was run alone.
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, 5*time.Second)
		req, reqErr := http.NewRequestWithContext(attemptCtx, http.MethodGet,
			fmt.Sprintf("http://127.0.0.1:%d/", agentPort), nil)
		if reqErr != nil {
			cancelAttempt()
			t.Fatalf("build the request: %v", reqErr)
		}
		// The agent inside serves one connection at a time, so reusing one
		// would arrive at a listener that has already moved on.
		req.Close = true
		resp, err = client.Do(req)
		if err == nil {
			defer cancelAttempt()
			break
		}
		cancelAttempt()
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("reaching the agent through the reverse channel: %v\nsandbox said:\n%s", err, out.String())
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the agent's answer: %v", err)
	}
	if !strings.Contains(string(body), served) {
		t.Errorf("the agent answered %q, want %q", string(body), served)
	}
}

// managerTransport exposes the transport the forwarder would use, so the test
// drives the same dialling the gateway does rather than a copy of it.
func managerTransport(t *testing.T, m *sambox.IngressManager) http.RoundTripper {
	t.Helper()
	tr := m.AgentTransport()
	if tr == nil {
		t.Fatal("no transport: with AgentSocket set the manager must dial the sandbox")
	}
	return tr
}

// lockedBuilder collects a subprocess's stdout and stderr, which arrive on
// different goroutines.
type lockedBuilder struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuilder) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuilder) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
