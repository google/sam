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
	authProvider     string
	oidcIssuer       string
	clientID         string
	clientSecret     string
	biscuitHex       string
	listenAddrs      []string
	meshName         string
	publicAddr       string
	httpAddr         string // Mandatory HTTP listener flag
	oauth2AuthURL    string
	oauth2TokenURL   string
	oauth2UserURL    string
	oauth2UserField  string
	oauth2EmailField string
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
	gater            *hubConnGate
	AuthProvider     string
	OAuth2UserURL    string
	OAuth2UserField  string
	OAuth2EmailField string
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

	var oidcConfig *oauth2.Config
	var verifier *oidc.IDTokenVerifier

	if authProvider == "oauth2" {
		oidcConfig = &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  oauth2AuthURL,
				TokenURL: oauth2TokenURL,
			},
			RedirectURL: fmt.Sprintf("%s/callback", publicAddr),
			Scopes:      []string{"user:email"},
		}
	} else {
		provider, err := oidc.NewProvider(ctx, oidcIssuer)
		if err != nil {
			return nil, err
		}
		oidcConfig = &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  fmt.Sprintf("%s/callback", publicAddr),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}
		verifier = provider.Verifier(&oidc.Config{ClientID: clientID})
	}

	// SAM_HUB_KEY stores an ed25519 seed as a 32-byte hex value.
	keyBytes, err := hex.DecodeString(biscuitHex)
	if err != nil || len(keyBytes) != 32 {
		return nil, fmt.Errorf("invalid SAM_HUB_KEY: must be 32-byte hex string")
	}
	bKey := ed25519.NewKeyFromSeed(keyBytes)

	hub := &Hub{
		Host:             h,
		DHT:              kadDHT,
		gater:            gater,
		OIDCConfig:       oidcConfig,
		Verifier:         verifier,
		BiscuitKey:       bKey,
		MeshID:           meshName,
		AuthProvider:     authProvider,
		OAuth2UserURL:    oauth2UserURL,
		OAuth2UserField:  oauth2UserField,
		OAuth2EmailField: oauth2EmailField,
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

// issueStandardBiscuit creates a biscuit with standard facts for user, email, groups, and hardware binding (peer ID).
func (h *Hub) issueStandardBiscuit(p peer.ID, sub string, email string, groups []string) (string, error) {
	builder := biscuit.NewBuilder(h.BiscuitKey)

	// user mapping (sub)
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "user",
		IDs:  []biscuit.Term{biscuit.String(sub)},
	}}); err != nil {
		return "", err
	}

	// email mapping (email)
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "email",
		IDs:  []biscuit.Term{biscuit.String(email)},
	}}); err != nil {
		return "", err
	}

	// group mapping (groups)
	for _, g := range groups {
		if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: "group",
			IDs:  []biscuit.Term{biscuit.String(g)},
		}}); err != nil {
			return "", err
		}
	}

	// peer_id mapping (hardware binding)
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(p.String())},
	}}); err != nil {
		return "", err
	}

	// mesh_id mapping (namespace)
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "namespace",
		IDs:  []biscuit.Term{biscuit.String(h.MeshID)},
	}}); err != nil {
		return "", err
	}

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

// startWatchdog periodically checks for peers that have connected but not completed OIDC
// authentication within the grace period, and evicts them from the network.
func (h *Hub) startWatchdog() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		for range ticker.C {
			h.gater.mu.Lock()
			now := time.Now()
			for pID, connectedAt := range h.gater.pending {
				if now.Sub(connectedAt) > GracePeriod {
					fmt.Printf("[Security] Evicting unauthenticated peer: %s\n", pID)
					if err := h.Host.Network().ClosePeer(pID); err != nil {
						log.Printf("closing unauthenticated peer %s: %v", pID, err)
					}
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
			// OIDC Endpoints
			mux.HandleFunc("/login", h.handleLogin)
			mux.HandleFunc("/callback", h.handleCallback)
			// API endpoints for agents to fetch config and peer registry
			mux.HandleFunc("/api/v1/config", h.handleConfig)
			mux.HandleFunc("/api/v1/peers", h.authMiddleware(h.handlePeers))

			// Corrected libp2phttp Serve logic
			// This allows agents to reach OIDC via libp2p streams
			listener, err := gostream.Listen(h.Host, p2phttp.DefaultP2PProtocol)
			if err != nil {
				log.Fatal(err)
			}
			defer func() {
				if err := listener.Close(); err != nil {
					log.Printf("closing p2p listener: %v", err)
				}
			}()
			// Serve the HTTP handler over libp2p streams
			go func() {
				server := &http.Server{
					Handler: mux,
				}
				if err := server.Serve(listener); err != nil {
					log.Printf("p2p http server exited: %v", err)
				}
			}()

			fmt.Printf("SAM Hub Online (QUIC + TCP)\n")
			fmt.Printf("MeshID: %s\n", h.MeshID)
			fmt.Printf("PeerID: %s\n", h.Host.ID())

			// Standard HTTP server for browser-based OIDC and config API
			fmt.Printf("Starting Standard HTTP Frontend on %s\n", httpAddr)
			log.Fatal(http.ListenAndServe(httpAddr, mux))
		},
	}

	rootCmd.Flags().StringVar(&authProvider, "auth-provider", "oidc", "Authentication provider (oidc or oauth2)")
	rootCmd.Flags().StringVar(&oidcIssuer, "issuer", os.Getenv("SAM_OIDC_ISSUER"), "OIDC Issuer URL")
	rootCmd.Flags().StringVar(&oauth2AuthURL, "oauth2-auth-url", "", "OAuth2 Authorization URL")
	rootCmd.Flags().StringVar(&oauth2TokenURL, "oauth2-token-url", "", "OAuth2 Token URL")
	rootCmd.Flags().StringVar(&oauth2UserURL, "oauth2-user-url", "", "OAuth2 User Info URL")
	rootCmd.Flags().StringVar(&oauth2UserField, "oauth2-user-field", "id", "JSON field for User ID")
	rootCmd.Flags().StringVar(&oauth2EmailField, "oauth2-email-field", "email", "JSON field for Email")
	rootCmd.Flags().StringVar(&clientID, "client-id", os.Getenv("SAM_OIDC_ID"), "OIDC Client ID")
	rootCmd.Flags().StringVar(&clientSecret, "client-secret", os.Getenv("SAM_OIDC_SECRET"), "OIDC Client Secret")
	rootCmd.Flags().StringVar(&biscuitHex, "key", os.Getenv("SAM_HUB_KEY"), "Hub Private Key (32-byte Hex)")
	rootCmd.Flags().StringSliceVar(&listenAddrs, "listen", []string{"/ip4/0.0.0.0/udp/4001/quic-v1", "/ip4/0.0.0.0/tcp/4002"}, "libp2p Listen Addrs")
	rootCmd.Flags().StringVar(&meshName, "mesh", "public-mesh", "Mesh federation name")
	rootCmd.Flags().StringVar(&publicAddr, "public-url", "http://localhost:8080", "Public URL for browser OIDC")
	rootCmd.Flags().StringVar(&httpAddr, "http-listen", ":8080", "Standard HTTP listen address for OIDC and Config")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
