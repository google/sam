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
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

func TestMultiMasterHub(t *testing.T) {
	cpBin := buildBinary(t, "./cmd/sam-control-plane")
	routerBin := buildBinary(t, "./cmd/sam-router")

	tmpDir := t.TempDir()

	// Create a mock policy file
	policyFile := filepath.Join(tmpDir, "policies.yaml")
	policyContent := `version: "v1alpha1"
bindings: []
roles: {}
`
	writePolicyWithRouter(t, policyFile, policyContent)

	portA := getFreePort(t)
	portB := getFreePort(t)
	routerPortA := getFreePort(t)
	routerPortB := getFreePort(t)

	// Mock OIDC
	oidcURL, mintToken := startCustomMockOIDC(t)

	routerJWT := mintToken(map[string]interface{}{
		"sub":    "router-integration-1",
		"groups": []string{"routers"},
	})

	nodeJWT := mintToken(map[string]interface{}{
		"sub": "mock-user",
	})

	jwtPath := filepath.Join(tmpDir, "jwt.txt")
	if err := os.WriteFile(jwtPath, []byte(nodeJWT), 0644); err != nil {
		t.Fatal(err)
	}

	dbPathA := filepath.Join(tmpDir, "cp_keysA.db")
	dbPathB := filepath.Join(tmpDir, "cp_keysB.db")
	// We override journal_mode to DELETE (disabling WAL) because WAL mode caches
	// transactions in a separate -wal file. Since this test copies dbPathA to dbPathB
	// while CP A is running, WAL mode would cause the copy to be stale/corrupt.
	// We also retain busy_timeout(5000) so that concurrent operations wait for locks
	// rather than returning SQLITE_BUSY immediately.
	dsnA := dbPathA + "?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)"
	dsnB := dbPathB + "?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)"

	// 1. Start Control Plane A temporarily to generate keyring
	cmdCP_A_temp := exec.Command(cpBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", portA),
		"--policy-file", policyFile,
		"--db-dsn", dsnA,
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
	)
	var stdoutCP_A_temp, stderrCP_A_temp safeBuffer
	cmdCP_A_temp.Stdout = &stdoutCP_A_temp
	cmdCP_A_temp.Stderr = &stderrCP_A_temp
	if err := cmdCP_A_temp.Start(); err != nil {
		t.Fatalf("failed to start temporary CP A: %v", err)
	}
	waitForControlPlane(t, portA)
	_ = cmdCP_A_temp.Process.Signal(os.Interrupt)
	_ = cmdCP_A_temp.Wait()
	t.Logf("Temp CP A Stderr:\n%s\nTemp CP A Stdout:\n%s", stderrCP_A_temp.String(), stdoutCP_A_temp.String())

	// 2. Copy CP A keys to CP B to share the key-ring
	keysData, err := os.ReadFile(dbPathA)
	if err != nil {
		t.Fatalf("Failed to read cp_keysA.db: %v", err)
	}
	if err := os.WriteFile(dbPathB, keysData, 0600); err != nil {
		t.Fatalf("Failed to write cp_keysB.db: %v", err)
	}

	// 3. Start CP A persistently
	cmdCP_A := exec.Command(cpBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", portA),
		"--policy-file", policyFile,
		"--db-dsn", dsnA,
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
	)
	var stdoutCP_A, stderrCP_A safeBuffer
	cmdCP_A.Stdout = &stdoutCP_A
	cmdCP_A.Stderr = &stderrCP_A
	if err := cmdCP_A.Start(); err != nil {
		t.Fatalf("failed to start CP A: %v", err)
	}
	defer func() { _ = cmdCP_A.Process.Kill(); _ = cmdCP_A.Wait() }()

	waitForControlPlane(t, portA)

	// 4. Start Router A (registered with CP A)
	cmdRouterA := exec.Command(routerBin,
		"--control-plane", fmt.Sprintf("http://127.0.0.1:%d", portA),
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", routerPortA),
		"--keys-path", filepath.Join(tmpDir, "router_keysA.db"),
		"--allow-loopback",
		"--oidc-token", routerJWT,
	)
	var stdoutRouterA, stderrRouterA safeBuffer
	cmdRouterA.Stdout = &stdoutRouterA
	cmdRouterA.Stderr = &stderrRouterA
	if err := cmdRouterA.Start(); err != nil {
		t.Fatalf("failed to start Router A: %v", err)
	}
	defer func() { _ = cmdRouterA.Process.Kill(); _ = cmdRouterA.Wait() }()

	// Wait for Router A to renew lease and register in CP A
	time.Sleep(3 * time.Second)

	// 5. Start Control Plane B (sharing CP A's keys)
	cmdCP_B := exec.Command(cpBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", portB),
		"--policy-file", policyFile,
		"--db-dsn", dsnB,
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
	)
	var stdoutCP_B, stderrCP_B safeBuffer
	cmdCP_B.Stdout = &stdoutCP_B
	cmdCP_B.Stderr = &stderrCP_B
	if err := cmdCP_B.Start(); err != nil {
		t.Fatalf("failed to start CP B: %v", err)
	}
	defer func() { _ = cmdCP_B.Process.Kill(); _ = cmdCP_B.Wait() }()

	waitForControlPlane(t, portB)

	// 5. Start Router B (registered with CP B)
	cmdRouterB := exec.Command(routerBin,
		"--control-plane", fmt.Sprintf("http://127.0.0.1:%d", portB),
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", routerPortB),
		"--keys-path", filepath.Join(tmpDir, "router_keysB.db"),
		"--allow-loopback",
		"--oidc-token", routerJWT,
	)
	var stdoutRouterB, stderrRouterB safeBuffer
	cmdRouterB.Stdout = &stdoutRouterB
	cmdRouterB.Stderr = &stderrRouterB
	if err := cmdRouterB.Start(); err != nil {
		t.Fatalf("failed to start Router B: %v", err)
	}
	defer func() { _ = cmdRouterB.Process.Kill(); _ = cmdRouterB.Wait() }()

	// Wait for Router B to renew lease and register in CP B
	time.Sleep(3 * time.Second)

	// 6. Fetch router peer IDs
	peerInfoListA := fetchActiveRouters(t, portA)
	if len(peerInfoListA) != 1 {
		t.Fatalf("expected 1 router registered on CP A, got %d", len(peerInfoListA))
	}
	peerIDA := peerInfoListA[0]

	peerInfoListB := fetchActiveRouters(t, portB)
	if len(peerInfoListB) != 1 {
		t.Fatalf("expected 1 router registered on CP B, got %d", len(peerInfoListB))
	}
	peerIDB := peerInfoListB[0]

	// ASSERT: Router A and Router B have unique Peer IDs
	if peerIDA == peerIDB {
		t.Fatalf("expected routers to have unique Peer IDs, but both got: %s", peerIDA)
	}

	t.Logf("Replicas successfully started. Router A: %s, Router B: %s", peerIDA, peerIDB)

	// 7. Start a client libp2p host to represent a node
	clientHost, err := libp2p.New(libp2p.NoListenAddrs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientHost.Close() }()

	pubKey := clientHost.Peerstore().PubKey(clientHost.ID())
	pubBytes, err := crypto.MarshalPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	clientBiscuit := enrollClientOnControlPlane(t, portB, clientHost.ID(), pubBytes, nodeJWT)

	// 9. Assert that client host can connect and authenticate directly with Router A (registered with CP A!)
	// This proves Router A accepts biscuits issued by CP B because they share the key-ring.
	routerAddrA, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/p2p/%s", routerPortA, peerIDA))
	if err != nil {
		t.Fatal(err)
	}
	routerInfoA, err := peer.AddrInfoFromP2pAddr(routerAddrA)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Connecting client host %s to Router A at %s...", clientHost.ID(), routerAddrA)
	ctxConnect, cancelConnect := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelConnect()
	if err := clientHost.Connect(ctxConnect, *routerInfoA); err != nil {
		t.Fatalf("failed to connect client to Router A: %v", err)
	}

	t.Log("Opening auth stream to Router A...")
	s, err := clientHost.NewStream(context.Background(), routerInfoA.ID, api.AuthProtocolID)
	if err != nil {
		t.Fatalf("failed to open auth stream: %v", err)
	}
	defer func() { _ = s.Close() }()

	t.Log("Writing auth frame with CP B biscuit to Router A...")
	writer := msgio.NewVarintWriter(s)
	authFrame := &api.AuthFrame{Biscuit: clientBiscuit}
	authFrameBytes, err := proto.Marshal(authFrame)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteMsg(authFrameBytes); err != nil {
		t.Fatalf("failed to write auth frame: %v", err)
	}

	t.Log("Reading auth response from Router A...")
	reader := msgio.NewVarintReaderSize(s, 1024*64)
	respMsg, err := reader.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read response from Router A: %v\nRouter A Stderr:\n%s\nRouter A Stdout:\n%s\nCP A Stderr:\n%s\nCP B Stderr:\n%s",
			err, stderrRouterA.String(), stdoutRouterA.String(), stderrCP_A.String(), stderrCP_B.String())
	}
	defer reader.ReleaseMsg(respMsg)

	var authResp api.AuthResponse
	if err := proto.Unmarshal(respMsg, &authResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !authResp.Success {
		t.Fatalf("mutual auth with Router A was rejected: %s\nRouter A Stderr:\n%s\nRouter A Stdout:\n%s\nCP A Stderr:\n%s\nCP B Stderr:\n%s",
			authResp.Error, stderrRouterA.String(), stdoutRouterA.String(), stderrCP_A.String(), stderrCP_B.String())
	}

	t.Log("Successfully verified multi-master control plane signature trust!")
}

func enrollClientOnControlPlane(t *testing.T, cpPort int, clientID peer.ID, pubBytes []byte, jwtToken string) []byte {
	t.Helper()

	req := &api.EnrollRequest{
		Jwt:       jwtToken,
		PeerId:    clientID.String(),
		PublicKey: pubBytes,
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(
		fmt.Sprintf("http://127.0.0.1:%d/register", cpPort),
		"application/octet-stream",
		bytes.NewReader(reqBytes),
	)
	if err != nil {
		t.Fatalf("failed to send enroll request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("enroll request failed with status %d: %s", resp.StatusCode, string(body))
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var enrollResp api.EnrollResponse
	if err := proto.Unmarshal(respBytes, &enrollResp); err != nil {
		t.Fatalf("failed to decode enroll response: %v", err)
	}

	return enrollResp.BiscuitToken
}
