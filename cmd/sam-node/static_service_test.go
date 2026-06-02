package main

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

func startMockLibp2pHub(t *testing.T) (peer.ID, string) {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("failed to create mock libp2p host: %v", err)
	}

	kdht, err := dht.New(context.Background(), h, dht.Mode(dht.ModeServer), dht.ProtocolPrefix("/sam"))
	if err != nil {
		t.Fatalf("failed to create DHT on mock hub: %v", err)
	}

	// Start HTTP server for enrollment
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

		resp := &api.EnrollResponse{
			BiscuitToken: []byte("mock-biscuit-token"),
			HubPublicKey: []byte("mock-hub-pub-key"),
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

func TestStaticServiceRegistrationRequiresConnection(t *testing.T) {
	// 1. Setup mock hub
	_, hubURL := startMockLibp2pHub(t)

	// 2. Create temp store
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// 3. Create dummy keys
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate libp2p key: %v", err)
	}

	// 4. Create Node with empty hub addrs initially
	node, err := NewSamNode(context.Background(), priv, nil, []multiaddr.Multiaddr{}, store, "test-mesh", "100ms", []string{"/ip4/127.0.0.1/tcp/0"}, false, nil, 24*time.Hour, true)
	if err != nil {
		t.Fatalf("failed to create node: %v", err)
	}
	defer func() {
		if err := node.Host.Close(); err != nil {
			t.Errorf("failed to close node host: %v", err)
		}
	}()

	// Stand up a real MCP upstream so MCPService.Init() can complete its handshake.
	upstream := httptest.NewServer(newFakeMCPHandler(t, []*mcp.Tool{}))
	defer upstream.Close()

	// 5. Try to register static services BEFORE connecting to hub
	services := []api.ServiceConfig{
		{
			Type:        "mcp",
			Name:        "test-service",
			Description: "Test Service",
			TargetURL:   upstream.URL,
		},
	}

	ctx := context.Background()
	err = node.RegisterStaticServices(ctx, services)
	if err == nil {
		t.Fatal("Expected RegisterStaticServices to fail before connecting to hub, but it succeeded")
	}
	if !strings.Contains(err.Error(), "timeout waiting for DHT to be ready") {
		t.Fatalf("Expected error to contain 'timeout waiting for DHT to be ready', got: %v", err)
	}

	// 6. Now enroll and connect to hub (which sets up DHT and hub connection)
	oldHubAddr := hubAddr
	hubAddr = hubURL
	defer func() { hubAddr = oldHubAddr }()

	err = node.Enroll(ctx, "dummy-jwt")
	if err != nil {
		t.Fatalf("failed to enroll: %v", err)
	}

	// Now that we are connected, try to register again!
	err = node.RegisterStaticServices(ctx, services)
	if err != nil {
		t.Fatalf("Expected RegisterStaticServices to succeed after enrollment, but failed: %v", err)
	}

	// Tear down the live MCP session so upstream.Close() can return.
	if err := node.UnregisterService(ctx, "test-service"); err != nil {
		t.Errorf("unregister: %v", err)
	}
}

func TestStaticServiceRegistrationCommandFailure(t *testing.T) {
	// 1. Setup mock hub
	_, hubURL := startMockLibp2pHub(t)

	// 2. Create temp store
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// 3. Create dummy keys
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate libp2p key: %v", err)
	}

	// 4. Create Node with empty hub addrs initially
	node, err := NewSamNode(context.Background(), priv, nil, []multiaddr.Multiaddr{}, store, "test-mesh", "100ms", []string{"/ip4/127.0.0.1/tcp/0"}, false, nil, 24*time.Hour, true)
	if err != nil {
		t.Fatalf("failed to create node: %v", err)
	}
	defer func() {
		if err := node.Host.Close(); err != nil {
			t.Errorf("failed to close node host: %v", err)
		}
	}()

	// 5. Enroll and connect to hub (which sets up DHT and hub connection)
	oldHubAddr := hubAddr
	hubAddr = hubURL
	defer func() { hubAddr = oldHubAddr }()

	ctx := context.Background()
	err = node.Enroll(ctx, "dummy-jwt")
	if err != nil {
		t.Fatalf("failed to enroll: %v", err)
	}

	// 6. Try to register a service with a non-existent command
	services := []api.ServiceConfig{
		{
			Type:        "mcp",
			Name:        "test-stdio-fail",
			Description: "Test Stdio Failure",
			Command:     []string{"/non-existent/binary"},
		},
	}

	err = node.RegisterStaticServices(ctx, services)
	if err == nil {
		t.Fatal("Expected RegisterStaticServices to fail with non-existent command, but it succeeded")
	}
	if !strings.Contains(err.Error(), "/non-existent/binary") {
		t.Fatalf("Expected error to mention the missing binary, got: %v", err)
	}
}
