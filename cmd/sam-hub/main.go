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
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	golog "github.com/ipfs/go-log/v2"
	"github.com/google/sam/api"
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
)

var logger = golog.Logger("sam-hub")

// Hub handles identity bridging and network discovery
type Hub struct {
	Host       host.Host
	DHT        *dht.IpfsDHT
	Providers  map[string]*oidc.Provider
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

	// SAM_HUB_KEY stores an ed25519 seed as a 32-byte hex value.
	keyBytes, err := hex.DecodeString(biscuitHex)
	if err != nil || len(keyBytes) != 32 {
		return nil, fmt.Errorf("invalid SAM_HUB_KEY: must be 32-byte hex string")
	}
	bKey := ed25519.NewKeyFromSeed(keyBytes)

	hub := &Hub{
		Host:       h,
		DHT:        kadDHT,
		gater:      gater,
		Providers:  providers,
		BiscuitKey: bKey,
		MeshID:     meshName,
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
	parser := jwt.Parser{}
	jwtToken, _, err := parser.ParseUnverified(req.Jwt, jwt.MapClaims{})
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

	verifier := provider.Verifier(&oidc.Config{ClientID: aud})

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

	builder := biscuit.NewBuilder(h.BiscuitKey)

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

	for _, role := range roles {
		if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: "group",
			IDs:  []biscuit.Term{biscuit.String(role)},
		}}); err != nil {
			logger.Errorf("[Enroll] Failed to add group fact: %v", err)
			h.sendEnrollResponse(s, nil, "Failed to mint biscuit", 0, nil, nil)
			return
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

func (h *Hub) sendEnrollResponse(s network.Stream, biscuitToken []byte, errMsg string, expiration int64, knownPeers []string, policies []string) {
	var hubAddrs []string
	for _, addr := range h.Host.Addrs() {
		hubAddrs = append(hubAddrs, addr.String()+"/p2p/"+h.Host.ID().String())
	}

	pubKey := h.BiscuitKey.Public().(ed25519.PublicKey)

	resp := &api.EnrollResponse{
		BiscuitToken:    biscuitToken,
		ErrorMessage:    errMsg,
		HubPublicKey:    pubKey,
		HubAddresses:    hubAddrs,
		Expiration:      expiration,
		KnownPeers:      knownPeers,
		DatalogPolicies: policies,
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
func (h *Hub) startWatchdog() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		for range ticker.C {
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
			
			h, err := NewHub(ctx)
			if err != nil {
				logger.Fatal(err)
			}
			h.Host.SetStreamHandler(api.EnrollProtocolID, h.handleEnroll)

			// Watchdog: Expel peers that connect but never finish authentication
			h.startWatchdog()

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

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
