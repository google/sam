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
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"io"
	"net/http"
	"net/http/httptest"
	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

// init forces the biscuit-go parser to build its underlying participle
// lexer and reflection caches synchronously at startup. This prevents
// a known data race when multiple goroutines parse facts concurrently.
func init() {
	_, _ = parser.FromStringFact(`warmup("cache")`)
}

func TestFallbackReEnrollment(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")

	// 1. Generate Keys for Biscuit
	pubA, _, _ := ed25519.GenerateKey(nil)
	pubB, privB, _ := ed25519.GenerateKey(nil)

	// 2. Generate Client Peer Identity BEFORE starting any libp2p hosts
	// This avoids data race with FromStringFact later!
	clientPriv, clientPub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := peer.IDFromPublicKey(clientPub)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Create Biscuit token signed by Key B (using pre-computed clientID)
	builder := biscuit.NewBuilder(privB)

	nodeFact, _ := parser.FromStringFact(fmt.Sprintf(`node("%s")`, clientID))
	if err := builder.AddAuthorityFact(nodeFact); err != nil {
		t.Fatal(err)
	}

	clientPeerFact, _ := parser.FromStringFact(fmt.Sprintf(`client_peer_id("%s")`, clientID))
	if err := builder.AddAuthorityFact(clientPeerFact); err != nil {
		t.Fatal(err)
	}

	toolFact, _ := parser.FromStringFact(`allow_mcp_tool("*")`)
	if err := builder.AddAuthorityFact(toolFact); err != nil {
		t.Fatal(err)
	}

	b, _ := builder.Build()

	// Verify it in test
	authorizer, err := b.Authorizer(pubB)
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := parser.FromStringPolicy("allow if true")
	authorizer.AddPolicy(policy)
	if err := authorizer.Authorize(); err != nil {
		t.Fatalf("Token generated in test is invalid: %v", err)
	}

	tokenBytes, _ := b.Serialize()

	// 4. Start Mock Hub with dynamic key response
	_, hubAddr := startMockHubDynamic(t, pubA, pubB)

	tmpHome := t.TempDir()
	env := append(os.Environ(),
		"HOME="+tmpHome,
		"XDG_CONFIG_HOME="+filepath.Join(tmpHome, ".config"),
	)

	// Create a dummy JWT file for fallback
	jwtPath := filepath.Join(tmpHome, "jwt.txt")
	if err := os.WriteFile(jwtPath, []byte("dummy-jwt"), 0644); err != nil {
		t.Fatal(err)
	}

	// 5. Run Node in background
	cmd := exec.Command(nodeBin, "run", "--hub", hubAddr, "--listen", "/ip4/127.0.0.1/tcp/0", "--jwt-path", jwtPath, "--bind-addr", "127.0.0.1:0", "--api-token", "dummy-token", "--allow-loopback")
	cmd.Dir = repoRoot(t)
	cmd.Env = env

	var stdout safeBuffer
	var stderr safeBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
	}()

	// Wait for it to be ready (print address)
	var out string
	for i := 0; i < 50; i++ {
		out = stdout.String() + stderr.String()
		if strings.Contains(out, "Listening on:") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !strings.Contains(out, "Listening on:") {
		t.Fatalf("Node failed to start or didn't print address in time.\nOutput:\n%s", out)
	}

	// 6. Extract Node address
	var nodeAddr string
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Listening on:") {
			idx := strings.Index(line, "[")
			idx2 := strings.Index(line, "]")
			if idx != -1 && idx2 != -1 {
				addrsStr := line[idx+1 : idx2]
				addrs := strings.Split(addrsStr, " ")
				for _, a := range addrs {
					if strings.Contains(a, "/tcp/") {
						nodeAddr = a
						break
					}
				}
			}
		}
	}

	if nodeAddr == "" {
		t.Fatalf("Failed to extract node address from output:\n%s", out)
	}

	// Extract Peer ID
	var nodePeerID string
	for _, line := range lines {
		if strings.Contains(line, "PeerID:") {
			parts := strings.Split(line, " ")
			if len(parts) >= 2 {
				nodePeerID = strings.TrimSpace(parts[len(parts)-1])
			}
		}
	}

	if nodePeerID == "" {
		t.Fatalf("Failed to extract node PeerID from output:\n%s", out)
	}

	nodeFullAddr := nodeAddr + "/p2p/" + nodePeerID

	// 7. Start client host with the pre-generated identity
	clientHost, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.Identity(clientPriv),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientHost.Close() }()

	targetAddr, err := multiaddr.NewMultiaddr(nodeFullAddr)
	if err != nil {
		t.Fatal(err)
	}
	targetInfo, err := peer.AddrInfoFromP2pAddr(targetAddr)
	if err != nil {
		t.Fatal(err)
	}

	if err := clientHost.Connect(context.Background(), *targetInfo); err != nil {
		t.Fatal(err)
	}

	// 8. Connect to Node via libp2p on api.MCPProtocolID
	s, err := clientHost.NewStream(context.Background(), targetInfo.ID, api.MCPProtocolID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	// 9. Send AuthFrame with token B
	writer := msgio.NewVarintWriter(s)
	authFrame := &api.AuthFrame{Biscuit: tokenBytes}
	authFrameBytes, _ := proto.Marshal(authFrame)
	if err := writer.WriteMsg(authFrameBytes); err != nil {
		t.Fatal(err)
	}

	// 10. Read response
	reader := msgio.NewVarintReaderSize(s, 1024*64)
	respMsg, err := reader.ReadMsg()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.ReleaseMsg(respMsg)

	var resp api.AuthResponse
	if err := proto.Unmarshal(respMsg, &resp); err != nil {
		t.Fatal(err)
	}

	if !resp.Success {
		t.Fatalf("Auth failed: %s\nNode Output:\n%s", resp.Error, stdout.String()+stderr.String())
	}

	// Verify log shows fallback was triggered
	out = stdout.String() + stderr.String()
	if !strings.Contains(out, "triggering re-enrollment fallback") {
		t.Errorf("Expected log to contain fallback trigger message\nNode Output:\n%s", out)
	}
}

func startMockHubDynamic(t *testing.T, pubA, pubB ed25519.PublicKey) (peer.ID, string) {
	t.Helper()

	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("failed to create mock libp2p host: %v", err)
	}

	h.SetStreamHandler(api.AuthProtocolID, func(s network.Stream) {
		defer func() { _ = s.Close() }()
		reader := msgio.NewVarintReaderSize(s, 1024*64)
		msg, err := reader.ReadMsg()
		if err != nil {
			return
		}
		defer reader.ReleaseMsg(msg)

		writer := msgio.NewVarintWriter(s)
		resp := &api.AuthResponse{Success: true}
		respBytes, _ := proto.Marshal(resp)
		_ = writer.WriteMsg(respBytes)
	})

	kdht, err := dht.New(context.Background(), h, dht.Mode(dht.ModeServer), dht.ProtocolPrefix("/sam"))
	if err != nil {
		t.Fatalf("failed to create DHT on mock hub: %v", err)
	}

	var callCount int
	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		var req api.EnrollRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		callCount++
		var pub []byte
		if callCount == 1 {
			pub = pubA
		} else {
			pub = pubB
		}

		resp := &api.EnrollResponse{
			BiscuitToken: []byte("mock-biscuit-token"),
			HubPublicKey: pub,
			HubAddresses: []string{h.Addrs()[0].String() + "/p2p/" + h.ID().String()},
			KnownPeers:   []string{},
		}
		data, err := proto.Marshal(resp)
		if err != nil {
			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	httpServer := httptest.NewServer(mux)

	t.Cleanup(func() {
		httpServer.Close()
		_ = kdht.Close()
		_ = h.Close()
	})

	return h.ID(), httpServer.URL
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
