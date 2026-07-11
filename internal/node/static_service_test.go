package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
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

	// Generate mock control plane keys
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CP keys: %v", err)
	}

	// Mint router's biscuit token
	builder := biscuit.NewBuilder(cpPriv)
	_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactNode,
		IDs:  []biscuit.Term{biscuit.String(h.ID().String())},
	}})
	_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactRole,
		IDs:  []biscuit.Term{biscuit.String(api.RoleRouter)},
	}})
	_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactExpiration,
		IDs:  []biscuit.Term{biscuit.Date(time.Now().Add(24 * time.Hour))},
	}})
	_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactTargetUnrestricted,
	}})
	tok, err := builder.Build()
	if err != nil {
		t.Fatalf("failed to build mock router biscuit: %v", err)
	}
	routerBiscuit, err := tok.Serialize()
	if err != nil {
		t.Fatalf("failed to serialize mock router biscuit: %v", err)
	}

	// Add dummy auth handler
	h.SetStreamHandler(api.AuthProtocolID, func(s network.Stream) {
		defer func() { _ = s.Close() }()
		// Mutual auth response
		resp := &api.AuthResponse{
			Success: true,
			Biscuit: routerBiscuit,
		}
		data, _ := proto.Marshal(resp)
		writer := msgio.NewVarintWriter(s)
		_ = writer.WriteMsg(data)
	})

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
			HubPublicKey: cpPub,
			HubAddresses: []string{h.Addrs()[0].String() + "/p2p/" + h.ID().String()},
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
	node, err := NewSamNode(Options{
		PrivKey:           priv,
		HubAddrs:          []multiaddr.Multiaddr{},
		Store:             store,
		MeshID:            "test-mesh",
		DiscoveryInterval: "100ms",
		ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
		EnableRelay:       false,
		NodeConfig:        nil,
		KeyGracePeriod:    24 * time.Hour,
		AllowLoopback:     true,
		MonitorBootstrap:  2 * time.Minute,
		MonitorInterval:   1 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create node: %v", err)
	}
	node.BiscuitTimeout = 1 * time.Second
	ctx := context.Background()
	if err := node.Start(ctx); err != nil {
		t.Fatalf("failed to start node: %v", err)
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

	err = node.RegisterStaticServices(ctx, services)
	if err == nil {
		t.Fatal("Expected RegisterStaticServices to fail before connecting to hub, but it succeeded")
	}
	if !strings.Contains(err.Error(), "timeout waiting for DHT to be ready") {
		t.Fatalf("Expected error to contain 'timeout waiting for DHT to be ready', got: %v", err)
	}

	// 6. Now enroll and connect to hub (which sets up DHT and hub connection)
	err = node.Enroll(ctx, hubURL, "dummy-jwt")
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
	node, err := NewSamNode(Options{
		PrivKey:           priv,
		HubAddrs:          []multiaddr.Multiaddr{},
		Store:             store,
		MeshID:            "test-mesh",
		DiscoveryInterval: "100ms",
		ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
		EnableRelay:       false,
		NodeConfig:        nil,
		KeyGracePeriod:    24 * time.Hour,
		AllowLoopback:     true,
		MonitorBootstrap:  2 * time.Minute,
		MonitorInterval:   1 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create node: %v", err)
	}
	node.BiscuitTimeout = 2 * time.Second
	ctx := context.Background()
	if err := node.Start(ctx); err != nil {
		t.Fatalf("failed to start node: %v", err)
	}
	defer func() {
		if err := node.Host.Close(); err != nil {
			t.Errorf("failed to close node host: %v", err)
		}
	}()

	// 5. Enroll and connect to hub (which sets up DHT and hub connection)
	err = node.Enroll(ctx, hubURL, "dummy-jwt")
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
