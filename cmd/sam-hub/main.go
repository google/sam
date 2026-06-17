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
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"sync"

	"github.com/libp2p/go-msgio"

	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"

	"golang.org/x/time/rate"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
)

func init() {
	if dnsServer := os.Getenv("SAM_TEST_DNS_SERVER"); dnsServer != "" {
		customResolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", dnsServer)
			},
		}
		net.DefaultResolver = customResolver
		madns.DefaultResolver, _ = madns.NewResolver(madns.WithDefaultResolver(customResolver))
	}
}

const (
	GracePeriod = 60 * time.Second

	// Rate limiting defaults
	EnrollRateLimit = 10
	EnrollBurst     = 20

	// ConnManager limits
	LowWaterMark    = 100
	HighWaterMark   = 400
	ConnGracePeriod = 1 * time.Minute

	// Timeouts
	JWTVerificationTimeout = 10 * time.Second

	// Defaults
	DefaultOIDCIssuer  = "https://accounts.google.com"
	DefaultMeshName    = "public-mesh"
	DefaultPolicyFile  = "policies.yaml"
	DefaultKeysDBPath  = "keys.db"
	DefaultBindAddress = ":9090"
)

var isHubReady atomic.Bool

var (
	oidcIssuer            string
	clientID              string
	biscuitHex            string
	listenAddrs           []string
	meshName              string
	insecureSkipTLSVerify bool
	logLevel              string
	policyFile            string
	keyRotationInterval   time.Duration
	keyGracePeriod        time.Duration
	keysDBPath            string
	bindAddress           string
	adminToken            string
	tlsCertFile           string
	tlsKeyFile            string
	tlsCAFile             string
	externalMultiaddrs    []string
	allowedAudiencesFlag  string
	allowLoopbackFlag     bool
)

var logger = golog.Logger("sam-hub")

type relayACL struct {
	hub *Hub
}

func (a *relayACL) AllowReserve(p peer.ID, addr multiaddr.Multiaddr) bool {
	_, ok := a.hub.authenticatedPeers.Load(p)
	if !ok {
		logger.Errorf("[Relay] Rejecting reservation for %s: not authenticated", p)
	} else {
		logger.Infof("[Relay] Allowing reservation for %s", p)
	}
	return ok
}

func (a *relayACL) AllowConnect(src peer.ID, srcAddr multiaddr.Multiaddr, dest peer.ID) bool {
	_, ok := a.hub.authenticatedPeers.Load(src)
	if !ok {
		logger.Errorf("[Relay] Rejecting connect from %s to %s: not authenticated", src, dest)
	} else {
		logger.Infof("[Relay] Allowing connect from %s to %s", src, dest)
	}
	return ok
}

// Hub handles identity bridging and network discovery
type Hub struct {
	Host               host.Host
	DHT                *dht.IpfsDHT
	Providers          map[string]*oidc.Provider
	KeyRing            *KeyRing
	MeshID             string
	PubSub             *pubsub.PubSub
	EventTopic         *pubsub.Topic
	Policy             *api.PolicyConfig
	limiter            *rate.Limiter
	ExternalAddrs      []string
	AllowedAudiences   []string
	AllowLoopback      bool
	authenticatedPeers sync.Map
}

// NewHub starts a host supporting both QUIC and TCP (with TLS 1.3)
func NewHub(ctx context.Context, policy *api.PolicyConfig, allowLoopback bool) (*Hub, error) {
	// Connection Manager for DoS protection
	cm, err := connmgr.NewConnManager(LowWaterMark, HighWaterMark, connmgr.WithGracePeriod(ConnGracePeriod))
	if err != nil {
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	opts := []libp2p.Option{
		libp2p.DefaultTransports,
		libp2p.ListenAddrStrings(listenAddrs...),
		// FIPS compliant Security
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.ConnectionManager(cm),
		libp2p.EnableAutoNATv2(),
		libp2p.EnableNATService(),
		libp2p.AddrsFactory(func(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			if allowLoopback {
				return addrs
			}
			var filtered []multiaddr.Multiaddr
			for _, addr := range addrs {
				if !isLoopbackOrLinkLocal(addr) {
					filtered = append(filtered, addr)
				}
			}
			return filtered
		}),
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}

	kadDHT, err := dht.New(ctx, h, dht.Mode(dht.ModeServer), dht.ProtocolPrefix("/sam"))
	if err != nil {
		return nil, err
	}
	if err = kadDHT.Bootstrap(ctx); err != nil {
		return nil, err
	}

	issuers := strings.Split(oidcIssuer, ",")
	providers := make(map[string]*oidc.Provider)
	for _, iss := range issuers {
		iss = strings.TrimSpace(iss)
		if iss == "" {
			continue
		}
		var providerCtx = ctx
		if insecureSkipTLSVerify {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client := &http.Client{
				Timeout:   30 * time.Second,
				Transport: tr,
			}
			providerCtx = oidc.ClientContext(ctx, client)
		}
		provider, err := oidc.NewProvider(providerCtx, iss)
		if err != nil {
			return nil, fmt.Errorf("failed to create provider for %s: %w", iss, err)
		}
		providers[iss] = provider
		logger.Infof("[OIDC] Trusted issuer: %s", iss)
	}

	var initialSeed []byte
	if biscuitHex != "" {
		var err error
		initialSeed, err = hex.DecodeString(strings.TrimSpace(biscuitHex))
		if err != nil {
			return nil, fmt.Errorf("failed to decode key flag: %w", err)
		}
	}
	kr, err := NewKeyRing(keysDBPath, keyGracePeriod, initialSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyring: %w", err)
	}

	var auds []string
	for _, aud := range strings.Split(allowedAudiencesFlag, ",") {
		aud = strings.TrimSpace(aud)
		if aud != "" {
			auds = append(auds, aud)
		}
	}
	if len(auds) == 0 {
		auds = []string{api.DefaultAudience}
	}

	hub := &Hub{
		Host:             h,
		DHT:              kadDHT,
		Providers:        providers,
		KeyRing:          kr,
		MeshID:           meshName,
		Policy:           policy,
		limiter:          rate.NewLimiter(rate.Limit(EnrollRateLimit), EnrollBurst),
		ExternalAddrs:    externalMultiaddrs,
		AllowedAudiences: auds,
		AllowLoopback:    allowLoopback,
	}
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, err
	}
	topic, err := ps.Join(api.GossipEvents)
	if err != nil {
		return nil, err
	}

	hub.PubSub = ps
	hub.EventTopic = topic

	_, err = relay.New(h, relay.WithACL(&relayACL{hub: hub}))
	if err != nil {
		return nil, err
	}

	h.SetStreamHandler(api.AuthProtocolID, hub.HandleAuthHandshake)

	h.Network().Notify(&network.NotifyBundle{
		DisconnectedF: func(n network.Network, c network.Conn) {
			p := c.RemotePeer()
			if len(h.Network().ConnsToPeer(p)) == 0 {
				hub.authenticatedPeers.Delete(p)
			}
		},
	})

	return hub, nil
}

func (h *Hub) parseAndVerifyJWT(ctx context.Context, jwtStr string, allowedAudiences []string) (jwt.MapClaims, *oidc.IDToken, error) {
	jwtParser := jwt.Parser{}
	jwtToken, _, err := jwtParser.ParseUnverified(jwtStr, jwt.MapClaims{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// 1. Defend against downgrade attacks immediately
	alg, ok := jwtToken.Header["alg"].(string)
	if !ok || alg == "" || strings.ToLower(alg) == "none" {
		return nil, nil, fmt.Errorf("invalid or missing alg header")
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, fmt.Errorf("invalid JWT claims")
	}
	iss, _ := claims["iss"].(string)

	// 2. Extract the audience
	var aud string
	switch a := claims["aud"].(type) {
	case string:
		aud = a
	case []any:
		if len(a) > 0 {
			aud, _ = a[0].(string)
		}
	}

	if aud == "" {
		return nil, nil, fmt.Errorf("missing aud claim")
	}

	// 3. Verify the audience matches one of your expected tenants/platforms
	validAudience := false
	for _, allowed := range allowedAudiences {
		if aud == allowed {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return nil, nil, fmt.Errorf("untrusted audience: %s", aud)
	}

	// 4. Route to the correct provider
	provider, ok := h.Providers[iss]
	if !ok {
		return nil, nil, fmt.Errorf("unknown issuer: %s", iss)
	}

	// 5. Verify cryptographic signature, bypassing the strict single-clientID check
	// because we already validated the audience against our allowed list above.
	verifier := provider.Verifier(&oidc.Config{
		SkipClientIDCheck: true,
	})

	token, err := verifier.Verify(ctx, jwtStr)
	if err != nil {
		return nil, nil, fmt.Errorf("JWT validation failed: %w", err)
	}

	return claims, token, nil
}

func (h *Hub) mintBiscuitToken(claims jwt.MapClaims, token *oidc.IDToken, remotePeer peer.ID) ([]byte, error) {
	var oidcRoles []string
	if rolesAny, ok := claims["roles"].([]any); ok {
		for _, r := range rolesAny {
			if str, ok := r.(string); ok && str != "" {
				oidcRoles = append(oidcRoles, str)
			}
		}
	}

	var oidcGroups []string
	if groupsAny, ok := claims["groups"].([]any); ok {
		for _, g := range groupsAny {
			if str, ok := g.(string); ok && str != "" {
				oidcGroups = append(oidcGroups, str)
			}
		}
	}

	oidcSub, _ := claims["sub"].(string)

	// Resolve roles based on configured bindings and explicit OIDC roles
	resolvedRoles := make(map[string]bool)
	if h.Policy != nil {
		// 1. Map OIDC groups and users to roles via configured bindings (RBAC mapping)
		for _, b := range h.Policy.Bindings {
			if b.Group != "" {
				for _, cg := range oidcGroups {
					if b.Group == cg {
						resolvedRoles[b.Role] = true
					}
				}
			}
			if b.User != "" && oidcSub != "" {
				if b.User == oidcSub {
					resolvedRoles[b.Role] = true
				}
			}
		}

		// 2. Validate and accept pre-resolved OIDC roles directly if defined in policy (Zero-Trust check)
		for _, r := range oidcRoles {
			if _, exists := h.Policy.Roles[r]; exists {
				resolvedRoles[r] = true
			}
		}
	}

	builder := biscuit.NewBuilder(h.KeyRing.GetCurrentKey())

	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactExpiration,
		IDs:  []biscuit.Term{biscuit.Date(token.Expiry)},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add expiration fact: %w", err)
	}

	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactNode,
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add node fact: %w", err)
	}

	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactClientPeerID,
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add client_peer_id fact: %w", err)
	}

	if oidcSub != "" {
		if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactUser,
			IDs:  []biscuit.Term{biscuit.String(oidcSub)},
		}}); err != nil {
			return nil, fmt.Errorf("failed to add user fact: %w", err)
		}
	}

	// Assert original OIDC groups in the token (semantic audit trail)
	seenGroups := make(map[string]bool)
	for _, cg := range oidcGroups {
		if seenGroups[cg] {
			continue
		}
		seenGroups[cg] = true
		if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactGroup,
			IDs:  []biscuit.Term{biscuit.String(cg)},
		}}); err != nil {
			return nil, fmt.Errorf("failed to add group fact: %w", err)
		}
	}

	// Assert resolved authorized roles in the token
	for role := range resolvedRoles {
		if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactRole,
			IDs:  []biscuit.Term{biscuit.String(role)},
		}}); err != nil {
			return nil, fmt.Errorf("failed to add role fact: %w", err)
		}

		if h.Policy != nil {
			if rolePolicy, ok := h.Policy.Roles[role]; ok {
				for _, tool := range rolePolicy.MCP.AllowedTools {
					if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
						Name: api.FactMCPTool,
						IDs:  []biscuit.Term{biscuit.String(tool)},
					}}); err != nil {
						logger.Errorw("Failed to add MCP tool fact to biscuit", "peer_id", remotePeer, "tool", tool, "error", err)
					}
				}
				for _, target := range rolePolicy.Network.AllowedTargets {
					if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
						Name: api.FactNetworkTarget,
						IDs:  []biscuit.Term{biscuit.String(target)},
					}}); err != nil {
						logger.Errorw("Failed to add network target fact to biscuit", "peer_id", remotePeer, "target", target, "error", err)
					}
				}
				for _, customFact := range rolePolicy.CustomDatalog {
					trimmed := strings.TrimRight(strings.TrimSpace(customFact), ";")
					if trimmed == "" {
						continue
					}
					func() {
						defer func() {
							if r := recover(); r != nil {
								logger.Errorw("Panic parsing custom fact", "peer_id", remotePeer, "fact", trimmed, "recover", r)
							}
						}()
						fact, err := parser.FromStringFact(trimmed)
						if err != nil {
							logger.Errorw("Failed to parse custom fact", "peer_id", remotePeer, "fact", trimmed, "error", err)
							return
						}
						if err := builder.AddAuthorityFact(fact); err != nil {
							logger.Errorw("Failed to add custom fact to biscuit", "peer_id", remotePeer, "fact", trimmed, "error", err)
						}
					}()
				}
			}
		}
	}

	t, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build biscuit: %w", err)
	}

	biscuitData, err := t.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize biscuit: %w", err)
	}

	return biscuitData, nil
}

// startWatchdog periodically checks for peers that have connected but not completed OIDC
// authentication within the grace period, and evicts them from the network.

func (h *Hub) startRotation(ctx context.Context) {
	if keyRotationInterval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(keyRotationInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				logger.Infow("Rotating keys")
				newPub, newPriv, oldPriv, err := h.KeyRing.PrepareRotation()
				if err != nil {
					logger.Errorw("Failed to prepare key rotation", "error", err)
					continue
				}
				samHubKeyRotationsTotal.Inc()

				// Broadcast event
				event := &api.MeshEvent{
					Type:         api.MeshEvent_KEY_ROTATION,
					Timestamp:    time.Now().UnixMilli(),
					NewPublicKey: newPub,
				}

				// Sign with the OLD key so nodes can verify it!
				event.Signature = nil
				data, err := proto.Marshal(event)
				if err != nil {
					logger.Errorw("Failed to marshal key rotation event", "error", err)
					continue
				}
				event.Signature = ed25519.Sign(oldPriv, data)

				eventData, err := proto.Marshal(event)
				if err != nil {
					logger.Errorw("Failed to marshal key rotation event", "error", err)
					continue
				}
				if err := h.EventTopic.Publish(ctx, eventData); err != nil {
					logger.Errorw("Failed to publish key rotation event", "error", err)
				} else {
					logger.Infow("Broadcasted new public key", "public_key", hex.EncodeToString(newPub))
					samHubMeshEventsTotal.WithLabelValues("KEY_ROTATION").Inc()

					// Promote the new key after successful broadcast
					if err := h.KeyRing.CommitRotation(newPub, newPriv, keyGracePeriod); err != nil {
						logger.Errorw("Failed to commit key rotation", "error", err)
					} else {
						logger.Infow("Committed new key to keyring")
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (h *Hub) signEvent(event *api.MeshEvent) error {
	event.Signature = nil
	data, err := proto.Marshal(event)
	if err != nil {
		return err
	}
	event.Signature = ed25519.Sign(h.KeyRing.GetCurrentKey(), data)
	return nil
}

func (h *Hub) PublishEvent(ctx context.Context, event *api.MeshEvent) error {
	if err := h.signEvent(event); err != nil {
		return err
	}
	data, err := proto.Marshal(event)
	if err != nil {
		return err
	}
	return h.EventTopic.Publish(ctx, data)
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "sam-hub",
		Short: "Sovereign Agent Mesh - Multi-Transport Hub",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			// Initialize logging
			if os.Getenv("LOG_FORMAT") == "json" {
				_ = os.Setenv("GOLOG_LOG_FMT", "json")
			}
			golog.SetAllLoggers(golog.LevelInfo)
			_ = golog.SetLogLevel("dht", "fatal")
			_ = golog.SetLogLevel("dht/RtRefreshManager", "fatal")
			if logLevel != "" {
				lvl, err := golog.LevelFromString(logLevel)
				if err == nil {
					golog.SetAllLoggers(lvl)
				}
			}

			policyConfig, err := LoadPolicyConfig(policyFile)
			if err != nil {
				logger.Fatal(err)
			}

			var serverTlsConfig *tls.Config
			if tlsCertFile != "" && tlsKeyFile != "" {
				cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
				if err != nil {
					logger.Fatalf("Failed to load TLS cert: %v", err)
				}
				serverTlsConfig = &tls.Config{
					Certificates: []tls.Certificate{cert},
				}
			}

			h, err := NewHub(ctx, policyConfig, allowLoopbackFlag)
			if err != nil {
				logger.Fatal(err)
			}

			// Start key rotation if enabled
			h.startRotation(ctx)

			if len(externalMultiaddrs) > 0 {
				go startBootstrapFederation(ctx, h, externalMultiaddrs)
			}

			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}))
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
				if isHubReady.Load() {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("ok"))
				} else {
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte("not ready"))
				}
			})

			mux.HandleFunc("/register", h.handleRegisterHTTP)
			mux.HandleFunc("/info", h.handleInfoHTTP)
			mux.HandleFunc("/admin/ban", func(w http.ResponseWriter, r *http.Request) {
				if adminToken != "" {
					authHeader := r.Header.Get("Authorization")
					if authHeader != "Bearer "+adminToken {
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}
				}
				handleBan(h)(w, r)
			})

			server := &http.Server{
				Addr:              bindAddress,
				Handler:           mux,
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       10 * time.Second,
				WriteTimeout:      10 * time.Second,
				IdleTimeout:       120 * time.Second,
			}

			go func() {
				if serverTlsConfig != nil {
					server.TLSConfig = serverTlsConfig
					if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
						logger.Fatalf("HTTP server failed: %v", err)
					}
				} else {
					if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						logger.Fatalf("HTTP server failed: %v", err)
					}
				}
			}()

			logger.Infof("SAM Hub Online (HTTP on %s, P2P on %v)", bindAddress, listenAddrs)
			isHubReady.Store(true)
			logger.Infof("MeshID: %s", h.MeshID)
			logger.Infof("PeerID: %s", h.Host.ID())
			<-ctx.Done()

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		},
	}

	defIssuer := os.Getenv("SAM_OIDC_ISSUER")
	if defIssuer == "" {
		defIssuer = DefaultOIDCIssuer
	}
	rootCmd.Flags().StringVar(&oidcIssuer, "issuer", defIssuer, "OIDC Issuer URL")
	rootCmd.Flags().StringVar(&clientID, "client-id", os.Getenv("SAM_OIDC_ID"), "OIDC Client ID")
	rootCmd.Flags().StringVar(&biscuitHex, "key", os.Getenv("SAM_HUB_KEY"), "Hub Private Key (32-byte Hex)")
	rootCmd.Flags().StringSliceVar(&listenAddrs, "listen", []string{}, "libp2p Listen Addrs")
	rootCmd.Flags().StringSliceVar(&externalMultiaddrs, "external-multiaddr", []string{}, "External multiaddrs to announce")
	rootCmd.Flags().StringVar(&meshName, "mesh", DefaultMeshName, "Mesh federation name")
	rootCmd.Flags().StringVar(&allowedAudiencesFlag, "allowed-audiences", api.DefaultAudience, "Comma-separated list of allowed OIDC audiences")
	rootCmd.Flags().BoolVar(&insecureSkipTLSVerify, "insecure-skip-tls-verify", false, "Skip TLS verification for OIDC issuers")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().StringVar(&policyFile, "policy-file", DefaultPolicyFile, "Path to policies.yaml")
	rootCmd.Flags().DurationVar(&keyRotationInterval, "key-rotation-interval", 0, "Key rotation interval (e.g. 12h). 0 disables rotation.")
	rootCmd.Flags().DurationVar(&keyGracePeriod, "key-grace-period", 24*time.Hour, "Key grace period for old keys (e.g. 24h).")
	rootCmd.Flags().StringVar(&keysDBPath, "keys-db", DefaultKeysDBPath, "Path to BoltDB file for keys")
	rootCmd.PersistentFlags().StringVar(&bindAddress, "bind-address", DefaultBindAddress, "Address to listen on for HTTP/HTTPS service")
	rootCmd.PersistentFlags().StringVar(&adminToken, "admin-token", "", "Secret token for authorizing admin requests")
	rootCmd.PersistentFlags().StringVar(&tlsCertFile, "tls-cert-file", "", "Path to TLS certificate for the server")
	rootCmd.PersistentFlags().StringVar(&tlsKeyFile, "tls-key-file", "", "Path to TLS private key for the server")
	rootCmd.PersistentFlags().StringVar(&tlsCAFile, "tls-ca-file", "", "Path to CA certificate to verify client certificates (enables mTLS)")
	rootCmd.Flags().BoolVar(&allowLoopbackFlag, "allow-loopback", false, "Allow publishing and connecting to loopback/link-local addresses")

	var peerToBan string
	var banReason string
	var connectAddr string

	adminCmd := &cobra.Command{
		Use:   "admin",
		Short: "Administrative commands for SAM Hub",
	}

	banCmd := &cobra.Command{
		Use:   "ban",
		Short: "Ban a peer from the mesh",
		Run: func(cmd *cobra.Command, args []string) {
			if peerToBan == "" {
				logger.Fatal("Missing --peer flag")
			}

			targetAddr := bindAddress
			if strings.HasPrefix(targetAddr, ":") {
				targetAddr = "localhost" + targetAddr
			}

			scheme := "http"
			var tlsConfig *tls.Config
			if tlsCertFile != "" || tlsCAFile != "" {
				scheme = "https"
				tlsConfig = &tls.Config{
					InsecureSkipVerify: true, // For tests, usually self-signed
				}
				if tlsCAFile != "" {
					caCert, err := os.ReadFile(tlsCAFile)
					if err != nil {
						logger.Fatalf("Failed to read CA cert: %v", err)
					}
					caCertPool := x509.NewCertPool()
					caCertPool.AppendCertsFromPEM(caCert)
					tlsConfig.RootCAs = caCertPool
					tlsConfig.InsecureSkipVerify = false // Verify if CA is provided!
				}
			}

			client := &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
			}

			url := fmt.Sprintf("%s://%s/admin/ban?peer=%s", scheme, targetAddr, peerToBan)
			req, err := http.NewRequest("POST", url, nil)
			if err != nil {
				logger.Fatalf("Failed to create request: %v", err)
			}

			if adminToken != "" {
				req.Header.Set("Authorization", "Bearer "+adminToken)
			}

			resp, err := client.Do(req)
			if err != nil {
				logger.Fatalf("Failed to send ban request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				logger.Fatalf("Ban request failed: %s", resp.Status)
			}

			fmt.Printf("Published BANNED event for peer %s\n", peerToBan)
		},
	}

	banCmd.Flags().StringVar(&peerToBan, "peer", "", "Peer ID to ban")
	banCmd.Flags().StringVar(&banReason, "reason", "", "Reason for banning")
	banCmd.Flags().StringVar(&connectAddr, "connect", "", "Address of a peer in the mesh to connect to")

	adminCmd.AddCommand(banCmd)
	rootCmd.AddCommand(adminCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func isLoopbackOrLinkLocal(addr multiaddr.Multiaddr) bool {
	for _, proto := range addr.Protocols() {
		if proto.Code == multiaddr.P_IP4 || proto.Code == multiaddr.P_IP6 {
			value, err := addr.ValueForProtocol(proto.Code)
			if err == nil {
				ip := net.ParseIP(value)
				if ip != nil {
					if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
						return true
					}
				}
			}
		}
	}
	return false
}

func (h *Hub) verifyBiscuit(biscuitData []byte, remotePeer peer.ID) (*biscuit.Biscuit, error) {
	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		return nil, fmt.Errorf("malformed biscuit: %w", err)
	}

	keys := h.KeyRing.GetAllValidPublicKeys()
	var lastErr error
	for _, pubKey := range keys {
		authorizer, err := b.Authorizer(pubKey)
		if err != nil {
			lastErr = err
			continue
		}

		rule, err := parser.FromStringPolicy("allow if true")
		if err != nil {
			lastErr = err
			continue
		}
		authorizer.AddPolicy(rule)

		if err := authorizer.Authorize(); err == nil {
			return b, nil
		} else {
			lastErr = err
		}
	}

	return nil, fmt.Errorf("no valid key found for verification: %v", lastErr)
}

func (h *Hub) HandleAuthHandshake(s network.Stream) {
	defer func() {
		if err := s.Close(); err != nil {
			logger.Debugf("[AuthN] Failed to close auth stream: %v", err)
		}
	}()
	remotePeer := s.Conn().RemotePeer()

	reader := msgio.NewVarintReaderSize(s, 1024*64)
	msg, err := reader.ReadMsg()
	if err != nil {
		logger.Errorf("[AuthN] Failed to read handshake from %s: %v", remotePeer, err)
		return
	}
	defer reader.ReleaseMsg(msg)

	var exchange api.AuthFrame
	if err := proto.Unmarshal(msg, &exchange); err != nil {
		logger.Warnf("[AuthN] Invalid protobuf from %s", remotePeer)
		return
	}

	b, err := h.verifyBiscuit(exchange.Biscuit, remotePeer)
	if err != nil {
		logger.Warnf("[AuthN] Authorization failed for %s: %v", remotePeer, err)
		return
	}

	// Enforce hardware binding
	boundFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}
	if _, err := b.GetBlockID(boundFact); err != nil {
		logger.Warnf("[AuthN] Token is not bound to peer %s", remotePeer)
		return
	}

	h.authenticatedPeers.Store(remotePeer, true)
	logger.Infof("[AuthN] Successfully authenticated peer %s", remotePeer)

	writer := msgio.NewVarintWriter(s)
	resp := &api.AuthResponse{Success: true}
	respBytes, _ := proto.Marshal(resp)
	if err := writer.WriteMsg(respBytes); err != nil {
		logger.Errorf("[AuthN] Failed to write ACK to %s: %v", remotePeer, err)
	}
}

func startBootstrapFederation(ctx context.Context, h *Hub, peers []string) {
	if len(peers) == 0 {
		return
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	connectBootstrap(ctx, h, peers)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			connectBootstrap(ctx, h, peers)
		}
	}
}

func connectBootstrap(ctx context.Context, h *Hub, peers []string) {
	for _, peerStr := range peers {
		ma, err := multiaddr.NewMultiaddr(peerStr)
		if err != nil {
			continue
		}
		resolvedAddrs, err := madns.DefaultResolver.Resolve(ctx, ma)
		if err != nil {
			resolvedAddrs = []multiaddr.Multiaddr{ma}
		}
		for _, resolved := range resolvedAddrs {
			pi, err := peer.AddrInfoFromP2pAddr(resolved)
			if err != nil || pi.ID == h.Host.ID() {
				continue
			}
			if len(h.Host.Network().ConnsToPeer(pi.ID)) == 0 {
				if err := h.Host.Connect(ctx, *pi); err == nil {
					logger.Infof("[Federation] Connected to bootstrap peer: %s via %s", pi.ID, peerStr)
				}
			}
		}
	}
}
