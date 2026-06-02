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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func TestMultiMasterHub(t *testing.T) {
	hubBin := buildBinary(t, "./cmd/sam-hub")
	tmpDir := t.TempDir()

	// Create a mock policy file
	policyFile := filepath.Join(tmpDir, "policies.yaml")
	policyContent := `version: "v1alpha1"
bindings: []
roles: {}
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	portA := getFreePort(t)
	portB := getFreePort(t)

	// Start Replica A
	cmdA := exec.Command(hubBin,
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", portA),
		"--bind-address", "127.0.0.1:0",
		"--policy-file", policyFile,
		"--keys-db", filepath.Join(tmpDir, "keysA.db"),
		"--allow-loopback",
	)
	var stdoutA, stderrA safeBuffer
	cmdA.Stdout = &stdoutA
	cmdA.Stderr = &stderrA

	if err := cmdA.Start(); err != nil {
		t.Fatalf("failed to start Hub Replica A: %v", err)
	}
	defer func() { _ = cmdA.Process.Kill() }()

	// Start Replica B
	cmdB := exec.Command(hubBin,
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", portB),
		"--bind-address", "127.0.0.1:0",
		"--policy-file", policyFile,
		"--keys-db", filepath.Join(tmpDir, "keysB.db"),
		"--allow-loopback",
	)
	var stdoutB, stderrB safeBuffer
	cmdB.Stdout = &stdoutB
	cmdB.Stderr = &stderrB

	if err := cmdB.Start(); err != nil {
		t.Fatalf("failed to start Hub Replica B: %v", err)
	}
	defer func() { _ = cmdB.Process.Kill() }()

	// Wait for both replicas to be online and parse their Peer IDs
	var peerIDA, peerIDB string
	for i := 0; i < 50; i++ {
		outA := stdoutA.String() + stderrA.String()
		outB := stdoutB.String() + stderrB.String()

		if peerIDA == "" {
			for _, line := range strings.Split(outA, "\n") {
				if strings.Contains(line, "PeerID:") {
					parts := strings.Split(line, " ")
					peerIDA = strings.TrimSpace(parts[len(parts)-1])
				}
			}
		}

		if peerIDB == "" {
			for _, line := range strings.Split(outB, "\n") {
				if strings.Contains(line, "PeerID:") {
					parts := strings.Split(line, " ")
					peerIDB = strings.TrimSpace(parts[len(parts)-1])
				}
			}
		}

		if peerIDA != "" && peerIDB != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if peerIDA == "" || peerIDB == "" {
		t.Fatalf("replicas failed to report Peer ID in time. A: %q, B: %q\nStdout A:\n%s\nStderr A:\n%s\nStdout B:\n%s\nStderr B:\n%s", peerIDA, peerIDB, stdoutA.String(), stderrA.String(), stdoutB.String(), stderrB.String())
	}

	// ASSERT: Both replicas must have different Peer IDs!
	if peerIDA == peerIDB {
		t.Fatalf("expected replicas to have unique Peer IDs, but both got: %s", peerIDA)
	}

	t.Logf("Replicas successfully started. Replica A: %s, Replica B: %s", peerIDA, peerIDB)

	// Create a separate libp2p client host
	clientHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientHost.Close() }()

	// Validate connecting to Replica A
	addrA, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/p2p/%s", portA, peerIDA))
	if err != nil {
		t.Fatal(err)
	}
	infoA, err := peer.AddrInfoFromP2pAddr(addrA)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Dialing Hub Replica A at %s...", addrA)
	ctxA, cancelA := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelA()
	if err := clientHost.Connect(ctxA, *infoA); err != nil {
		t.Fatalf("failed to connect to Hub Replica A: %v", err)
	}
	t.Log("Successfully connected and authenticated with Hub Replica A!")

	// Validate connecting to Replica B
	addrB, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/p2p/%s", portB, peerIDB))
	if err != nil {
		t.Fatal(err)
	}
	infoB, err := peer.AddrInfoFromP2pAddr(addrB)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Dialing Hub Replica B at %s...", addrB)
	ctxB, cancelB := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelB()
	if err := clientHost.Connect(ctxB, *infoB); err != nil {
		t.Fatalf("failed to connect to Hub Replica B: %v", err)
	}
	t.Log("Successfully connected and authenticated with Hub Replica B!")
}
