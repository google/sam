package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/spf13/cobra"

	"sam/pkg/identity"
	samnet "sam/pkg/net"

	"github.com/multiformats/go-multiaddr"
)

func main() {
	cmd := &cobra.Command{
		Use:   "sam-hub",
		Short: "SAM hub: passport issuer, key manager, and trust observer",
	}

	cmd.AddCommand(newKeygenCmd())
	cmd.AddCommand(newServeCmd())

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "sam-hub: %v\n", err)
		os.Exit(1)
	}
}

func newKeygenCmd() *cobra.Command {
	var includeIdentity bool
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate hub keys (signing and/or peer identity)",
		RunE: func(_ *cobra.Command, _ []string) error {
			// Always generate signing key
			_, signingPriv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("generating signing key: %w", err)
			}
			signingB64 := base64.RawURLEncoding.EncodeToString(signingPriv)
			signingPub := base64.RawURLEncoding.EncodeToString(signingPriv.Public().(ed25519.PublicKey))

			fmt.Printf("\n=== Passport Signing Key ===\n")
			fmt.Printf("Environment: SAM_HUB_KEY\n")
			fmt.Printf("Private (base64):\n%s\n\n", signingB64)
			fmt.Printf("Public (base64):\n%s\n\n", signingPub)

			// Optionally generate peer identity key for libp2p
			if includeIdentity {
				idPriv, err := samnet.GenerateKey()
				if err != nil {
					return fmt.Errorf("generating identity key: %w", err)
				}
				idBytes, err := crypto.MarshalPrivateKey(idPriv)
				if err != nil {
					return fmt.Errorf("marshaling identity key: %w", err)
				}
				idB64 := base64.RawURLEncoding.EncodeToString(idBytes)

				fmt.Printf("=== Hub Peer Identity Key (for libp2p) ===\n")
				fmt.Printf("Environment: SAM_HUB_IDENTITY_KEY\n")
				fmt.Printf("Private (base64):\n%s\n\n", idB64)
				fmt.Printf("Usage: Configure as bootstrap peer for agents to discover the hub.\n")
			}

			return nil
		},
	}
	cmd.Flags().BoolVar(&includeIdentity, "with-identity", false, "also generate peer identity key for libp2p host")
	return cmd
}

func newServeCmd() *cobra.Command {
	var (
		httpListen string
		p2pListen  string
		enableP2P  bool
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the hub HTTP server (and optionally libp2p host)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Optionally start libp2p host for peer discovery/rendezvous
			var node samnet.Node
			if enableP2P {
				idPriv, err := loadOrGenerateIdentityKey()
				if err != nil {
					return fmt.Errorf("loading identity key: %w", err)
				}
				listenAddrs, err := parseMultiaddrs(p2pListen)
				if err != nil {
					return fmt.Errorf("parsing p2p listen addresses: %w", err)
				}
				if len(listenAddrs) == 0 {
					listenAddrs = samnet.DefaultOptions().ListenAddrs
				}
				node, err = samnet.New(
					samnet.WithPrivateKey(idPriv),
					samnet.WithListenAddrs(listenAddrs...),
					samnet.WithDHTMode(samnet.DHTModeServer),
					samnet.WithRelayService(),
				)
				if err != nil {
					return fmt.Errorf("creating libp2p node: %w", err)
				}
				if err := node.Start(context.Background()); err != nil {
					return fmt.Errorf("starting libp2p node: %w", err)
				}
				defer func() { _ = node.Stop(context.Background()) }()
				fmt.Printf("libp2p host listening:\n")
				for _, addr := range node.Addrs() {
					fmt.Printf("  %s/p2p/%s\n", addr, node.PeerID())
				}
			}

			// Capture node reference for the P2P info endpoint closure.
			p2pNode := node

			mux := http.NewServeMux()
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			})
			mux.HandleFunc("/.well-known/sam-hub-keys", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"issuer": identity.DefaultHubIssuer,
					"keys": []map[string]string{{
						"kid": "sam-hub-root-v1",
						"alg": "Ed25519",
						"k":   identity.HubPublicKeyBase64(),
					}},
				})
			})
			mux.HandleFunc("/issue-passport", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				auth := strings.TrimSpace(r.Header.Get("Authorization"))
				if !strings.HasPrefix(strings.ToLower(auth), "bearer ") || strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == "" {
					http.Error(w, "missing bearer token", http.StatusUnauthorized)
					return
				}
				var req passportRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
					return
				}
				meshID := strings.TrimSpace(req.MeshID)
				if meshID == "" {
					meshID = strings.TrimSpace(req.Federation)
				}
				tok, err := identity.IssuePassportBiscuit(context.Background(), identity.PassportIssueRequest{
					PeerID:       strings.TrimSpace(req.PeerID),
					FederationID: meshID,
					Subject:      strings.TrimSpace(req.Subject),
					Claims:       map[string]string{"email": strings.TrimSpace(req.Email)},
				})
				if err != nil {
					http.Error(w, fmt.Sprintf("issue failed: %v", err), http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer":           identity.DefaultHubIssuer,
					"passport_biscuit": tok,
				})
			})
			// /.well-known/sam-hub-p2p advertises the hub's libp2p peer ID and
			// multiaddrs so agents can bootstrap and rendezvous via the hub
			// without needing out-of-band address configuration.
			mux.HandleFunc("/.well-known/sam-hub-p2p", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				if p2pNode == nil {
					http.Error(w, "hub is not running in P2P mode", http.StatusServiceUnavailable)
					return
				}
				addrs := make([]string, 0, len(p2pNode.Addrs()))
				for _, a := range p2pNode.Addrs() {
					addrs = append(addrs, fmt.Sprintf("%s/p2p/%s", a, p2pNode.PeerID()))
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"peer_id": p2pNode.PeerID().String(),
					"addrs":   addrs,
				})
			})
			mux.HandleFunc("/trust-map", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"source": "gossipsub", "note": "passive observer endpoint"})
			})
			srv := &http.Server{Addr: httpListen, Handler: mux}
			go func() {
				<-cmd.Context().Done()
				_ = srv.Shutdown(context.Background())
			}()
			fmt.Printf("hub HTTP listening on %s\n", httpListen)
			return srv.ListenAndServe()
		},
	}
	cmd.Flags().StringVar(&httpListen, "http-listen", ":8081", "HTTP server listen address")
	cmd.Flags().StringVar(&p2pListen, "p2p-listen", "", "libp2p listen multiaddrs (comma-separated; default: QUIC+TCP on all interfaces)")
	cmd.Flags().BoolVar(&enableP2P, "enable-p2p", false, "run libp2p host for peer discovery and rendezvous")
	return cmd
}

type passportRequest struct {
	PeerID     string `json:"peer_id"`
	Federation string `json:"federation"`
	MeshID     string `json:"mesh_id"`
	Subject    string `json:"subject"`
	Email      string `json:"email"`
}

// loadOrGenerateIdentityKey loads the hub's libp2p peer identity from SAM_HUB_IDENTITY_KEY
// environment variable (base64-encoded private key), or generates a new one.
func loadOrGenerateIdentityKey() (crypto.PrivKey, error) {
	if keyB64 := strings.TrimSpace(os.Getenv("SAM_HUB_IDENTITY_KEY")); keyB64 != "" {
		keyBytes, err := base64.RawURLEncoding.DecodeString(keyB64)
		if err != nil {
			return nil, fmt.Errorf("decoding SAM_HUB_IDENTITY_KEY: %w", err)
		}
		priv, err := crypto.UnmarshalPrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling SAM_HUB_IDENTITY_KEY: %w", err)
		}
		return priv, nil
	}
	return samnet.GenerateKey()
}

// parseMultiaddrs parses comma-separated multiaddr strings.
func parseMultiaddrs(addrStr string) ([]multiaddr.Multiaddr, error) {
	if strings.TrimSpace(addrStr) == "" {
		return nil, nil
	}
	var out []multiaddr.Multiaddr
	for _, s := range strings.Split(addrStr, ",") {
		if s = strings.TrimSpace(s); s != "" {
			// This is a stub; actual implementation would use multiaddr.NewMultiaddr
			ma, err := multiaddr.NewMultiaddr(s)
			if err != nil {
				return nil, err
			}
			out = append(out, ma)
		}
	}
	return out, nil
}
