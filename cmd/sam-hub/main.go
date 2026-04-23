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
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/libp2p/go-libp2p"
	p2phttp "github.com/libp2p/go-libp2p-http"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
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

const (
	GracePeriod = 60 * time.Second
)

var (
	oidcIssuer   string
	clientID     string
	clientSecret string
	biscuitHex   string
	listenAddrs  []string
	meshName     string
	publicAddr   string
)

// Hub handles identity bridging and network discovery
type Hub struct {
	Host       host.Host
	DHT        *dht.IpfsDHT
	OIDCConfig *oauth2.Config
	Verifier   *oidc.IDTokenVerifier
	BiscuitKey ed25519.PrivateKey
	MeshID     string
	PubSub     *pubsub.PubSub
	EventTopic *pubsub.Topic
	gater      *hubConnGate
}

// NewHub starts a host supporting both QUIC and TCP (with TLS 1.3)
func NewHub(ctx context.Context) (*Hub, error) {
	gater := newHubConnGate()
	// Multi-transport setup for firewall traversal
	h, err := libp2p.New(
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.ListenAddrStrings(listenAddrs...),
		// FIPS compliant Security
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.EnableRelayService(),
		libp2p.ConnectionGater(gater),
		libp2p.EnableNATService(),
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

	// SAM_HUB_KEY stores an ed25519 seed as a 32-byte hex value.
	keyBytes, err := hex.DecodeString(biscuitHex)
	if err != nil || len(keyBytes) != 32 {
		return nil, fmt.Errorf("invalid SAM_HUB_KEY: must be 32-byte hex string")
	}
	bKey := ed25519.NewKeyFromSeed(keyBytes)

	hub := &Hub{
		Host:  h,
		DHT:   kadDHT,
		gater: gater,
		OIDCConfig: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  fmt.Sprintf("%s/callback", publicAddr),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		Verifier:   provider.Verifier(&oidc.Config{ClientID: clientID}),
		BiscuitKey: bKey,
		MeshID:     meshName,
	}

	h.Network().Notify(&notifier{hub: hub})
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, err
	}
	topic, err := ps.Join("sam/mesh/events/v1")
	if err != nil {
		return nil, err
	}
	hub.PubSub = ps
	hub.EventTopic = topic
	return hub, nil
}

func (h *Hub) handleLogin(w http.ResponseWriter, r *http.Request) {
	pID := r.URL.Query().Get("peer_id")
	if pID == "" {
		http.Error(w, "Missing peer_id", 400)
		return
	}
	// Bind PeerID as the OIDC 'state'
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
	// standard claims mapping
	var claims struct {
		Subject string   `json:"sub"`
		Email   string   `json:"email"`
		Groups  []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse claims", 500)
		return
	}

	p, err := peer.Decode(peerIDStr)
	if err != nil {
		http.Error(w, "Invalid peer_id", 400)
		return
	}

	// Issue the Biscuit using Standard Vocabulary
	biscuitToken, err := h.issueStandardBiscuit(p, claims.Subject, claims.Email, claims.Groups)
	if err != nil {
		http.Error(w, "Biscuit issuance failed", 500)
		return
	}

	// Unlock the Mesh Firewall for this PeerID
	h.gater.mu.Lock()
	h.gater.authenticated[p] = true
	delete(h.gater.pending, p)
	h.gater.mu.Unlock()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<html><body>
		<h3>Sovereign Identity Verified!</h3>
		<p>Peer <code>%s</code> is now part of mesh <code>%s</code></p>
		<p>Identity: <code>%s</code></p>
		<hr/>
		<p>Standard Identity Biscuit:</p>
		<textarea rows="5" cols="60">%s</textarea>
	</body></html>`, p, h.MeshID, claims.Email, biscuitToken)
}

func (h *Hub) issueStandardBiscuit(p peer.ID, sub string, email string, groups []string) (string, error) {
	builder := biscuit.NewBuilder(h.BiscuitKey)

	// user_id mapping (sub)
	builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "user_id",
		IDs:  []biscuit.Term{biscuit.String(sub)},
	}})

	// user_email mapping (email)
	builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "user_email",
		IDs:  []biscuit.Term{biscuit.String(email)},
	}})

	// group mapping (groups)
	for _, g := range groups {
		builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: "group",
			IDs:  []biscuit.Term{biscuit.String(g)},
		}})
	}

	// peer_id mapping (hardware binding)
	builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "peer_id",
		IDs:  []biscuit.Term{biscuit.String(p.String())},
	}})

	// mesh_id mapping (namespace)
	builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "mesh_id",
		IDs:  []biscuit.Term{biscuit.String(h.MeshID)},
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

func (h *Hub) startWatchdog() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		for range ticker.C {
			h.gater.mu.Lock()
			now := time.Now()
			for pID, connectedAt := range h.gater.pending {
				if now.Sub(connectedAt) > GracePeriod {
					fmt.Printf("[Security] Evicting unauthenticated peer: %s\n", pID)
					h.Host.Network().ClosePeer(pID)
					delete(h.gater.pending, pID)
				}
			}
			h.gater.mu.Unlock()
		}
	}()
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

			// Watchdog: Expel peers that connect but never finish OIDC
			h.startWatchdog()

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
