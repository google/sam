package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/libp2p/go-libp2p"
	p2phttp "github.com/libp2p/go-libp2p-http"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/gostream"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

// Hub handles identity bridging and network discovery
type Hub struct {
	Host       host.Host
	DHT        *dht.IpfsDHT
	OIDCConfig *oauth2.Config
	Verifier   *oidc.IDTokenVerifier
	BiscuitKey ed25519.PrivateKey
	MeshID     string
	Registry   map[peer.ID]string
	mu         sync.RWMutex
}

var (
	oidcIssuer   string
	clientID     string
	clientSecret string
	biscuitHex   string
	listenAddrs  []string
	meshName     string
	publicAddr   string
)

// NewHub starts a host supporting both QUIC and TCP (with TLS 1.3)
func NewHub(ctx context.Context) (*Hub, error) {
	// Multi-transport setup for firewall traversal
	h, err := libp2p.New(
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.ListenAddrStrings(listenAddrs...),
		// FIPS compliant Security
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.EnableRelayService(),
	)
	if err != nil {
		return nil, err
	}

	_, err = relay.New(h)
	if err != nil {
		return nil, err
	}

	kadDHT, err := dht.New(ctx, h, dht.Mode(dht.ModeServer))
	if err != nil {
		return nil, err
	}
	if err = kadDHT.Bootstrap(ctx); err != nil {
		return nil, err
	}

	provider, err := oidc.NewProvider(ctx, oidcIssuer)
	if err != nil {
		return nil, err
	}

	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  fmt.Sprintf("%s/callback", publicAddr),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// SAM_HUB_KEY stores an ed25519 seed as a 32-byte hex value.
	keyBytes, err := hex.DecodeString(biscuitHex)
	if err != nil || len(keyBytes) != 32 {
		return nil, fmt.Errorf("invalid SAM_HUB_KEY: must be 32-byte hex string")
	}
	bKey := ed25519.NewKeyFromSeed(keyBytes)

	return &Hub{
		Host:       h,
		DHT:        kadDHT,
		OIDCConfig: conf,
		Verifier:   provider.Verifier(&oidc.Config{ClientID: clientID}),
		BiscuitKey: bKey,
		MeshID:     meshName,
		Registry:   make(map[peer.ID]string),
	}, nil
}

func (h *Hub) handleLogin(w http.ResponseWriter, r *http.Request) {
	pID := r.URL.Query().Get("peer_id")
	if pID == "" {
		http.Error(w, "Missing peer_id", 400)
		return
	}
	url := h.OIDCConfig.AuthCodeURL(pID)
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *Hub) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	peerIDStr := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	token, err := h.OIDCConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Token exchange failed", 500)
		return
	}

	rawID, _ := token.Extra("id_token").(string)
	idToken, err := h.Verifier.Verify(ctx, rawID)
	if err != nil {
		http.Error(w, "ID Token verification failed", 401)
		return
	}

	var claims struct {
		Email string `json:"email"`
	}
	idToken.Claims(&claims)

	p, err := peer.Decode(peerIDStr)
	if err != nil {
		http.Error(w, "Invalid peer_id", 400)
		return
	}

	bToken, err := h.issueBiscuit(p, claims.Email)
	if err != nil {
		http.Error(w, "Failed to issue Biscuit", 500)
		return
	}

	h.mu.Lock()
	h.Registry[p] = claims.Email
	h.mu.Unlock()

	fmt.Fprintf(w, "Sovereign Identity Verified!\nUser: %s\nToken: %s", claims.Email, bToken)
}

func (h *Hub) issueBiscuit(p peer.ID, email string) (string, error) {
	builder := biscuit.NewBuilder(h.BiscuitKey)

	builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "peer_id",
		IDs:  []biscuit.Term{biscuit.String(p.String())},
	}})
	builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "mesh_id",
		IDs:  []biscuit.Term{biscuit.String(h.MeshID)},
	}})
	builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "external_id",
		IDs:  []biscuit.Term{biscuit.String(email)},
	}})

	t, err := builder.Build()
	if err != nil {
		return "", err
	}

	data, err := t.Serialize()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "sam-hub",
		Short: "Sovereign Agent Mesh - Multi-Transport Hub",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()
			h, err := NewHub(ctx)
			if err != nil {
				log.Fatal(err)
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/login", h.handleLogin)
			mux.HandleFunc("/callback", h.handleCallback)

			// Corrected libp2phttp Serve logic
			// This allows agents to reach OIDC via libp2p streams
			listener, err := gostream.Listen(h.Host, p2phttp.DefaultP2PProtocol)
			if err != nil {
				log.Fatal(err)
			}
			defer listener.Close()
			go func() {
				server := &http.Server{
					Handler: mux,
				}
				server.Serve(listener)
			}()

			fmt.Printf("SAM Hub Online (QUIC + TCP)\n")
			fmt.Printf("MeshID: %s\n", h.MeshID)
			fmt.Printf("PeerID: %s\n", h.Host.ID())

			// Still need a port for the Browser to reach the Hub for OIDC redirect
			log.Fatal(http.ListenAndServe(":8080", mux))
		},
	}

	rootCmd.Flags().StringVar(&oidcIssuer, "issuer", os.Getenv("SAM_OIDC_ISSUER"), "OIDC Issuer URL")
	rootCmd.Flags().StringVar(&clientID, "client-id", os.Getenv("SAM_OIDC_ID"), "OIDC Client ID")
	rootCmd.Flags().StringVar(&clientSecret, "client-secret", os.Getenv("SAM_OIDC_SECRET"), "OIDC Client Secret")
	rootCmd.Flags().StringVar(&biscuitHex, "key", os.Getenv("SAM_HUB_KEY"), "Hub Private Key (32-byte Hex)")
	rootCmd.Flags().StringSliceVar(&listenAddrs, "listen", []string{"/ip4/0.0.0.0/udp/4001/quic-v1", "/ip4/0.0.0.0/tcp/4002"}, "libp2p Listen Addrs")
	rootCmd.Flags().StringVar(&meshName, "mesh", "public-mesh", "Mesh federation name")
	rootCmd.Flags().StringVar(&publicAddr, "public-url", "http://localhost:8080", "Public URL for browser OIDC")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
