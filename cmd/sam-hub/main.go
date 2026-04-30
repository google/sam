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
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
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
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-msgio"

	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
)

const (
	GracePeriod = 60 * time.Second
)

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
)

var logger = golog.Logger("sam-hub")

// Hub handles identity bridging and network discovery
type Hub struct {
	Host       host.Host
	DHT        *dht.IpfsDHT
	Providers  map[string]*oidc.Provider
	KeyRing    *KeyRing
	MeshID     string
	PubSub     *pubsub.PubSub
	EventTopic *pubsub.Topic
	gater      *hubConnGate
	Policy     *api.PolicyConfig
}

// NewHub starts a host supporting both QUIC and TCP (with TLS 1.3)
func NewHub(ctx context.Context, policy *api.PolicyConfig) (*Hub, error) {
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
			client := &http.Client{Transport: tr}
			providerCtx = oidc.ClientContext(ctx, client)
		}
		provider, err := oidc.NewProvider(providerCtx, iss)
		if err != nil {
			return nil, fmt.Errorf("failed to create provider for %s: %w", iss, err)
		}
		providers[iss] = provider
		logger.Infof("[OIDC] Trusted issuer: %s", iss)
	}

	kr, err := NewKeyRing(keysDBPath, keyGracePeriod)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyring: %w", err)
	}

	hub := &Hub{
		Host:      h,
		DHT:       kadDHT,
		gater:     gater,
		Providers: providers,
		KeyRing:   kr,
		MeshID:    meshName,
		Policy:    policy,
	}

	h.Network().Notify(&notifier{hub: hub})
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
	return hub, nil
}

func (h *Hub) handleEnroll(s network.Stream) {
	defer func() {
		_ = s.Close()
	}()
	remotePeer := s.Conn().RemotePeer()
	logger.Infof("[Enroll] New enrollment request from %s", remotePeer)

	reader := msgio.NewVarintReaderSize(s, 1024*64)
	msg, err := reader.ReadMsg()
	if err != nil {
		logger.Errorf("[Enroll] Failed to read message: %v", err)
		return
	}
	defer reader.ReleaseMsg(msg)

	var req api.EnrollRequest
	if err := proto.Unmarshal(msg, &req); err != nil {
		logger.Errorf("[Enroll] Failed to unmarshal request: %v", err)
		return
	}

	if req.PeerId != remotePeer.String() {
		logger.Warnf("[Enroll] Peer ID mismatch: %s != %s", req.PeerId, remotePeer)
		h.sendEnrollResponse(s, nil, "Peer ID mismatch", 0, nil, nil)
		return
	}

	// Parse JWT unverified to get issuer and audience
	jwtParser := jwt.Parser{}
	jwtToken, _, err := jwtParser.ParseUnverified(req.Jwt, jwt.MapClaims{})
	if err != nil {
		logger.Errorf("[Enroll] Failed to parse JWT: %v", err)
		h.sendEnrollResponse(s, nil, "Failed to parse JWT", 0, nil, nil)
		return
	}
	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		logger.Warn("[Enroll] Invalid JWT claims")
		h.sendEnrollResponse(s, nil, "Invalid JWT claims", 0, nil, nil)
		return
	}
	iss, _ := claims["iss"].(string)

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
		logger.Warn("[Enroll] Missing aud claim")
		h.sendEnrollResponse(s, nil, "Missing aud claim", 0, nil, nil)
		return
	}

	alg, ok := jwtToken.Header["alg"].(string)
	if !ok || alg == "" {
		logger.Warn("[Enroll] Missing alg header")
		h.sendEnrollResponse(s, nil, "Missing alg header", 0, nil, nil)
		return
	}

	provider, ok := h.Providers[iss]
	if !ok {
		logger.Warnf("[Enroll] Unknown issuer: %s", iss)
		h.sendEnrollResponse(s, nil, fmt.Sprintf("Unknown issuer: %s", iss), 0, nil, nil)
		return
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	token, err := verifier.Verify(context.Background(), req.Jwt)
	if err != nil {
		logger.Errorf("[Enroll] JWT validation failed: %v", err)
		h.sendEnrollResponse(s, nil, fmt.Sprintf("JWT validation failed: %v", err), 0, nil, nil)
		return
	}

	// Strictly enforce aud and alg after verification
	if alg == "none" {
		logger.Warnf("[Enroll] Invalid alg claim: %s", alg)
		h.sendEnrollResponse(s, nil, "Invalid alg claim", 0, nil, nil)
		return
	}
	logger.Infof("[Enroll] JWT validated with aud: %s, alg: %s", aud, alg)

	var roles []string
	if rolesAny, ok := claims["roles"].([]any); ok {
		for _, r := range rolesAny {
			if str, ok := r.(string); ok {
				roles = append(roles, str)
			}
		}
	}

	builder := biscuit.NewBuilder(h.KeyRing.GetCurrentKey())

	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "expiration",
		IDs:  []biscuit.Term{biscuit.Date(token.Expiry)},
	}}); err != nil {
		logger.Errorf("[Enroll] Failed to add expiration fact: %v", err)
		h.sendEnrollResponse(s, nil, "Failed to mint biscuit", 0, nil, nil)
		return
	}

	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}); err != nil {
		logger.Errorf("[Enroll] Failed to add node fact: %v", err)
		h.sendEnrollResponse(s, nil, "Failed to mint biscuit", 0, nil, nil)
		return
	}

	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "client_peer_id",
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}); err != nil {
		logger.Errorf("[Enroll] Failed to add client_peer_id fact: %v", err)
		h.sendEnrollResponse(s, nil, "Failed to mint biscuit", 0, nil, nil)
		return
	}

	for _, role := range roles {
		if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: "group",
			IDs:  []biscuit.Term{biscuit.String(role)},
		}}); err != nil {
			logger.Errorf("[Enroll] Failed to add group fact: %v", err)
			h.sendEnrollResponse(s, nil, "Failed to mint biscuit", 0, nil, nil)
			return
		}

		if h.Policy != nil {
			if rolePolicy, ok := h.Policy.Roles[role]; ok {
				for _, tool := range rolePolicy.MCP.AllowedTools {
					if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
						Name: api.FactMCPTool,
						IDs:  []biscuit.Term{biscuit.String(tool)},
					}}); err != nil {
						logger.Errorf("[Enroll] Failed to add fact %s: %v", api.FactMCPTool, err)
					}
				}
				for _, target := range rolePolicy.Network.AllowedTargets {
					if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
						Name: api.FactNetworkTarget,
						IDs:  []biscuit.Term{biscuit.String(target)},
					}}); err != nil {
						logger.Errorf("[Enroll] Failed to add fact %s: %v", api.FactNetworkTarget, err)
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
								logger.Errorf("[Enroll] Panic parsing custom fact %q: %v", trimmed, r)
							}
						}()
						fact, err := parser.FromStringFact(trimmed)
						if err != nil {
							logger.Errorf("[Enroll] Failed to parse custom fact %q: %v", trimmed, err)
							return
						}
						if err := builder.AddAuthorityFact(fact); err != nil {
							logger.Errorf("[Enroll] Failed to add custom fact %s: %v", trimmed, err)
						}
					}()
				}
			}
		}
	}

	t, err := builder.Build()
	if err != nil {
		logger.Errorf("[Enroll] Failed to build biscuit: %v", err)
		h.sendEnrollResponse(s, nil, "Failed to build biscuit", 0, nil, nil)
		return
	}

	biscuitData, err := t.Serialize()
	if err != nil {
		logger.Errorf("[Enroll] Failed to serialize biscuit: %v", err)
		h.sendEnrollResponse(s, nil, "Failed to serialize biscuit", 0, nil, nil)
		return
	}

	h.gater.mu.Lock()
	h.gater.authenticated[remotePeer] = true
	delete(h.gater.pending, remotePeer)

	// Collect authenticated peers
	var knownPeers []string
	for p := range h.gater.authenticated {
		knownPeers = append(knownPeers, p.String())
	}
	h.gater.mu.Unlock()

	policies := []string{
		`allow if operation($op)`,
	}

	h.sendEnrollResponse(s, biscuitData, "", token.Expiry.Unix(), knownPeers, policies)
	logger.Infof("[Enroll] Successfully enrolled peer %s", remotePeer)

	// Publish JOIN event
	event := &api.MeshEvent{
		Type:      api.MeshEvent_JOIN,
		PeerId:    remotePeer.String(),
		Timestamp: time.Now().Unix(),
	}
	if err := h.signEvent(event); err != nil {
		logger.Errorf("[Enroll] Failed to sign event: %v", err)
	} else {
		eventData, err := proto.Marshal(event)
		if err != nil {
			logger.Errorf("[Enroll] Failed to marshal event: %v", err)
		} else {
			if err := h.EventTopic.Publish(context.Background(), eventData); err != nil {
				logger.Errorf("[Enroll] Failed to publish event: %v", err)
			} else {
				logger.Infof("[Enroll] Published JOIN event for %s", remotePeer)
			}
		}
	}
}

func (h *Hub) sendEnrollResponse(s network.Stream, biscuitToken []byte, errMsg string, expiration int64, knownPeers []string, policies []string) {
	var hubAddrs []string
	for _, addr := range h.Host.Addrs() {
		hubAddrs = append(hubAddrs, addr.String()+"/p2p/"+h.Host.ID().String())
	}

	pubKey := h.KeyRing.GetCurrentPublicKey()

	resp := &api.EnrollResponse{
		BiscuitToken: biscuitToken,
		ErrorMessage: errMsg,
		HubPublicKey: pubKey,
		HubAddresses: hubAddrs,
		Expiration:   expiration,
		KnownPeers:   knownPeers,
	}
	data, err := proto.Marshal(resp)
	if err != nil {
		logger.Errorf("[Enroll] Failed to marshal response: %v", err)
		return
	}
	writer := msgio.NewVarintWriter(s)
	if err := writer.WriteMsg(data); err != nil {
		logger.Errorf("[Enroll] Failed to write response: %v", err)
	}
}

// startWatchdog periodically checks for peers that have connected but not completed OIDC
// authentication within the grace period, and evicts them from the network.
func (h *Hub) startWatchdog(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			select {
			case <-ctx.Done():
				return
			default:
			}
			h.gater.mu.Lock()
			now := time.Now()
			for pID, connectedAt := range h.gater.pending {
				if now.Sub(connectedAt) > GracePeriod {
					logger.Warnf("[Security] Evicting unauthenticated peer: %s", pID)
					if err := h.Host.Network().ClosePeer(pID); err != nil {
						logger.Errorf("[Security] Closing unauthenticated peer %s: %v", pID, err)
					}
					delete(h.gater.pending, pID)
				}
			}
			h.gater.mu.Unlock()
		}
	}()
}

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
				logger.Info("[Rotation] Rotating keys...")
				newPub, oldPriv, err := h.KeyRing.Rotate(keyGracePeriod)
				if err != nil {
					logger.Errorf("[Rotation] Failed to rotate keys: %v", err)
					continue
				}

				// Broadcast event
				event := &api.MeshEvent{
					Type:         api.MeshEvent_KEY_ROTATION,
					Timestamp:    time.Now().Unix(),
					NewPublicKey: newPub,
				}
				
				// Sign with the OLD key so nodes can verify it!
				event.Signature = nil
				data, err := proto.Marshal(event)
				if err != nil {
					logger.Errorf("[Rotation] Failed to marshal event: %v", err)
					continue
				}
				event.Signature = ed25519.Sign(oldPriv, data)

				eventData, err := proto.Marshal(event)
				if err != nil {
					logger.Errorf("[Rotation] Failed to marshal event: %v", err)
					continue
				}
				if err := h.EventTopic.Publish(ctx, eventData); err != nil {
					logger.Errorf("[Rotation] Failed to publish event: %v", err)
				} else {
					logger.Infof("[Rotation] Broadcasted new public key: %x", newPub)
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

func main() {
	rootCmd := &cobra.Command{
		Use:   "sam-hub",
		Short: "Sovereign Agent Mesh - Multi-Transport Hub",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()

			// Initialize logging
			golog.SetAllLoggers(golog.LevelInfo)
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

			h, err := NewHub(ctx, policyConfig)
			if err != nil {
				logger.Fatal(err)
			}
			h.Host.SetStreamHandler(api.EnrollProtocolID, h.handleEnroll)

			// Start key rotation if enabled
			h.startRotation(ctx)

			// Watchdog: Expel peers that connect but never finish authentication
			h.startWatchdog(ctx)

			logger.Infof("SAM Hub Online (QUIC + TCP)")
			logger.Infof("MeshID: %s", h.MeshID)
			logger.Infof("PeerID: %s", h.Host.ID())

			logger.Infof("Hub running on P2P transports only.")
			select {}
		},
	}

	defIssuer := os.Getenv("SAM_OIDC_ISSUER")
	if defIssuer == "" {
		defIssuer = "https://accounts.google.com"
	}
	rootCmd.Flags().StringVar(&oidcIssuer, "issuer", defIssuer, "OIDC Issuer URL")
	rootCmd.Flags().StringVar(&clientID, "client-id", os.Getenv("SAM_OIDC_ID"), "OIDC Client ID")
	rootCmd.Flags().StringVar(&biscuitHex, "key", os.Getenv("SAM_HUB_KEY"), "Hub Private Key (32-byte Hex)")
	rootCmd.Flags().StringSliceVar(&listenAddrs, "listen", []string{"/ip4/0.0.0.0/udp/8080/quic-v1", "/ip4/0.0.0.0/tcp/8080"}, "libp2p Listen Addrs")
	rootCmd.Flags().StringVar(&meshName, "mesh", "public-mesh", "Mesh federation name")
	rootCmd.Flags().BoolVar(&insecureSkipTLSVerify, "insecure-skip-tls-verify", false, "Skip TLS verification for OIDC issuers")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().StringVar(&policyFile, "policy-file", "policies.yaml", "Path to policies.yaml")
	rootCmd.Flags().DurationVar(&keyRotationInterval, "key-rotation-interval", 0, "Key rotation interval (e.g. 12h). 0 disables rotation.")
	rootCmd.Flags().DurationVar(&keyGracePeriod, "key-grace-period", 24*time.Hour, "Key grace period for old keys (e.g. 24h).")
	rootCmd.Flags().StringVar(&keysDBPath, "keys-db", "keys.db", "Path to BoltDB file for keys")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
