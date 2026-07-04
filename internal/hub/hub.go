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

package hub

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
)

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
)

type relayACL struct {
	hub *Hub
}

func (a *relayACL) AllowReserve(p peer.ID, addr multiaddr.Multiaddr) bool {
	_, ok := a.hub.authenticatedPeers.Load(p)
	if !ok {
		if a.hub.logger != nil {
			a.hub.logger.Errorf("[Relay] Rejecting reservation for %s: not authenticated", p)
		}
	} else {
		if a.hub.logger != nil {
			a.hub.logger.Infof("[Relay] Allowing reservation for %s", p)
		}
	}
	return ok
}

func (a *relayACL) AllowConnect(src peer.ID, srcAddr multiaddr.Multiaddr, dest peer.ID) bool {
	_, ok := a.hub.authenticatedPeers.Load(dest)
	if !ok {
		if a.hub.logger != nil {
			a.hub.logger.Errorf("[Relay] Rejecting connect from %s to %s: dest not authenticated", src, dest)
		}
	} else {
		if a.hub.logger != nil {
			a.hub.logger.Infof("[Relay] Allowing connect from %s to %s", src, dest)
		}
	}
	return ok
}

// Hub handles identity bridging and network discovery
type Hub struct {
	config                Options
	Host                  host.Host
	DHT                   *dht.IpfsDHT
	Providers             map[string]*oidc.Provider
	KeyRing               *KeyRing
	MeshID                string
	PubSub                *pubsub.PubSub
	EventTopic            *pubsub.Topic
	Policy                *api.PolicyConfig
	limiter               *rate.Limiter
	ExternalAddrs         []string
	AllowedAudiences      []string
	AllowLoopback         bool
	BiscuitTimeout        time.Duration
	authenticatedPeers    sync.Map
	logger                *golog.ZapEventLogger
	oidcIssuer            string
	keyRotationInterval   time.Duration
	keyGracePeriod        time.Duration
	insecureSkipTLSVerify bool
	isReady               atomic.Bool
}

// NewHub initializes configuration and KeyRing without starting background tasks or network interfaces.
func NewHub(config Options) (*Hub, error) {
	config.Default()
	if err := config.Validate(); err != nil {
		return nil, err
	}

	var initialSeed []byte
	if config.BiscuitHex != "" {
		var err error
		initialSeed, err = hex.DecodeString(strings.TrimSpace(config.BiscuitHex))
		if err != nil {
			return nil, fmt.Errorf("failed to decode key flag: %w", err)
		}
	}
	kr, err := NewKeyRing(config.KeysDBPath, config.KeyGracePeriod, initialSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyring: %w", err)
	}

	hub := &Hub{
		config:                config,
		KeyRing:               kr,
		MeshID:                config.MeshName,
		Policy:                config.Policy,
		limiter:               rate.NewLimiter(rate.Limit(EnrollRateLimit), EnrollBurst),
		AllowedAudiences:      config.AllowedAudiences,
		AllowLoopback:         config.AllowLoopback,
		logger:                golog.Logger("sam-hub"),
		oidcIssuer:            config.OIDCIssuer,
		keyRotationInterval:   config.KeyRotationInterval,
		keyGracePeriod:        config.KeyGracePeriod,
		insecureSkipTLSVerify: config.InsecureSkipTLSVerify,
	}

	return hub, nil
}

// Start initializes the libp2p host, DHT, PubSub, OIDC providers, and starts runtime components.
func (h *Hub) Start(ctx context.Context) error {
	// Connection Manager for DoS protection
	cm, err := connmgr.NewConnManager(LowWaterMark, HighWaterMark, connmgr.WithGracePeriod(ConnGracePeriod))
	if err != nil {
		return fmt.Errorf("failed to create connection manager: %w", err)
	}

	p2pOpts := []libp2p.Option{
		libp2p.DefaultTransports,
		libp2p.ListenAddrStrings(h.config.ListenAddrs...),
		// FIPS compliant Security
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.ConnectionManager(cm),
		libp2p.EnableAutoNATv2(),
		libp2p.EnableNATService(),
		libp2p.AddrsFactory(func(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			if h.config.AllowLoopback {
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

	hostNode, err := libp2p.New(p2pOpts...)
	if err != nil {
		return err
	}
	h.Host = hostNode

	kadDHT, err := dht.New(ctx, hostNode, dht.Mode(dht.ModeServer), dht.ProtocolPrefix("/sam"))
	if err != nil {
		return err
	}
	h.DHT = kadDHT

	if err = kadDHT.Bootstrap(ctx); err != nil {
		return err
	}

	issuers := strings.Split(h.config.OIDCIssuer, ",")
	providers := make(map[string]*oidc.Provider)
	for _, iss := range issuers {
		iss = strings.TrimSpace(iss)
		if iss == "" {
			continue
		}
		var providerCtx = ctx
		if h.config.InsecureSkipTLSVerify {
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
			return fmt.Errorf("failed to create provider for %s: %w", iss, err)
		}
		providers[iss] = provider
	}
	h.Providers = providers

	var filteredExternal []string
	for _, addr := range h.config.ExternalMultiaddrs {
		if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
			filteredExternal = append(filteredExternal, addr)
		}
	}
	h.ExternalAddrs = filteredExternal

	ps, err := pubsub.NewGossipSub(ctx, hostNode)
	if err != nil {
		return err
	}
	h.PubSub = ps

	topic, err := ps.Join(api.GossipEvents)
	if err != nil {
		return err
	}
	h.EventTopic = topic

	_, err = relay.New(hostNode, relay.WithACL(&relayACL{hub: h}))
	if err != nil {
		return err
	}

	hostNode.SetStreamHandler(api.AuthProtocolID, h.HandleAuthHandshake)

	hostNode.Network().Notify(&network.NotifyBundle{
		DisconnectedF: func(n network.Network, c network.Conn) {
			p := c.RemotePeer()
			if len(hostNode.Network().ConnsToPeer(p)) == 0 {
				h.authenticatedPeers.Delete(p)
			}
		},
	})

	h.logger.Infof("[OIDC] Trusted issuers: %s", h.config.OIDCIssuer)

	// Start key rotation if enabled
	h.StartRotation(ctx)

	// Start bootstrap federation if enabled
	if len(h.config.ExternalMultiaddrs) > 0 {
		go h.StartBootstrapFederation(ctx, h.config.ExternalMultiaddrs)
	}

	return nil
}

// Ready returns the ready status of the Hub.
func (h *Hub) Ready() bool {
	return h.isReady.Load()
}

// SetReady sets the ready status of the Hub.
func (h *Hub) SetReady(ready bool) {
	h.isReady.Store(ready)
}

// Close closes the underlying p2p host and keyring db.
func (h *Hub) Close() error {
	var errs []error
	if h.DHT != nil {
		if err := h.DHT.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if h.Host != nil {
		if err := h.Host.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if h.KeyRing != nil {
		if err := h.KeyRing.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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

// StartRotation periodically checks for keys to rotate.
func (h *Hub) StartRotation(ctx context.Context) {
	if h.keyRotationInterval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(h.keyRotationInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				h.logger.Infow("Rotating keys")
				newPub, newPriv, oldPriv, err := h.KeyRing.PrepareRotation()
				if err != nil {
					h.logger.Errorw("Failed to prepare key rotation", "error", err)
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
					h.logger.Errorw("Failed to marshal key rotation event", "error", err)
					continue
				}
				event.Signature = ed25519.Sign(oldPriv, data)

				eventData, err := proto.Marshal(event)
				if err != nil {
					h.logger.Errorw("Failed to marshal key rotation event", "error", err)
					continue
				}
				if err := h.EventTopic.Publish(ctx, eventData); err != nil {
					h.logger.Errorw("Failed to publish key rotation event", "error", err)
				} else {
					h.logger.Infow("Broadcasted new public key", "public_key", hex.EncodeToString(newPub))
					samHubMeshEventsTotal.WithLabelValues("KEY_ROTATION").Inc()

					// Promote the new key after successful broadcast
					if err := h.KeyRing.CommitRotation(newPub, newPriv, h.keyGracePeriod); err != nil {
						h.logger.Errorw("Failed to commit key rotation", "error", err)
					} else {
						h.logger.Infow("Committed new key to keyring")
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

// PublishEvent signs and broadcasts a mesh event.
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

// HandleAuthHandshake processes the inbound auth protocol handshake.
func (h *Hub) HandleAuthHandshake(s network.Stream) {
	defer func() {
		if err := s.Close(); err != nil {
			h.logger.Debugf("[AuthN] Failed to close auth stream: %v", err)
		}
	}()
	remotePeer := s.Conn().RemotePeer()

	reader := msgio.NewVarintReaderSize(s, 1024*64)
	msg, err := reader.ReadMsg()
	if err != nil {
		h.logger.Errorf("[AuthN] Failed to read handshake from %s: %v", remotePeer, err)
		return
	}
	defer reader.ReleaseMsg(msg)

	var exchange api.AuthFrame
	if err := proto.Unmarshal(msg, &exchange); err != nil {
		h.logger.Warnf("[AuthN] Invalid protobuf from %s", remotePeer)
		return
	}

	b, err := h.verifyBiscuit(exchange.Biscuit, remotePeer)
	if err != nil {
		h.logger.Warnf("[AuthN] Authorization failed for %s: %v", remotePeer, err)
		return
	}

	// Enforce hardware binding
	boundFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}
	if _, err := b.GetBlockID(boundFact); err != nil {
		h.logger.Warnf("[AuthN] Token is not bound to peer %s", remotePeer)
		return
	}

	h.authenticatedPeers.Store(remotePeer, true)
	h.logger.Infof("[AuthN] Successfully authenticated peer %s", remotePeer)

	writer := msgio.NewVarintWriter(s)
	resp := &api.AuthResponse{Success: true}
	respBytes, _ := proto.Marshal(resp)
	if err := writer.WriteMsg(respBytes); err != nil {
		h.logger.Errorf("[AuthN] Failed to write ACK to %s: %v", remotePeer, err)
	}
}

// StartBootstrapFederation handles background bootstrap federation.
func (h *Hub) StartBootstrapFederation(ctx context.Context, peers []string) {
	if len(peers) == 0 {
		return
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	h.connectBootstrap(ctx, peers)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.connectBootstrap(ctx, peers)
		}
	}
}

func (h *Hub) connectBootstrap(ctx context.Context, peers []string) {
	for _, peerStr := range peers {
		if strings.HasPrefix(peerStr, "http://") || strings.HasPrefix(peerStr, "https://") {
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Get(peerStr + "/info")
			if err != nil {
				h.logger.Errorf("[Federation] HTTP Get error for %s: %v", peerStr, err)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				h.logger.Errorf("[Federation] HTTP Get for %s returned status %d", peerStr, resp.StatusCode)
				_ = resp.Body.Close()
				continue
			}
			bodyBytes, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				h.logger.Errorf("[Federation] ReadAll error: %v", err)
				continue
			}

			var info api.HubInfoResponse
			if err := proto.Unmarshal(bodyBytes, &info); err != nil {
				h.logger.Errorf("[Federation] Proto unmarshal error: %v", err)
				continue
			}

			for _, addrStr := range info.HubAddresses {
				ma, err := multiaddr.NewMultiaddr(addrStr)
				if err != nil {
					h.logger.Errorf("[Federation] Multiaddr error: %v", err)
					continue
				}

				pi, err := peer.AddrInfoFromP2pAddr(ma)
				if err != nil {
					h.logger.Errorf("[Federation] AddrInfo error: %v", err)
					continue
				}

				if pi.ID == h.Host.ID() {
					continue
				}

				if len(h.Host.Network().ConnsToPeer(pi.ID)) > 0 {
					continue
				}

				if err := h.Host.Connect(ctx, *pi); err == nil {
					h.logger.Infof("[Federation] Connected to bootstrap peer: %s via HTTP %s", pi.ID, peerStr)
				} else {
					h.logger.Errorf("[Federation] Failed to connect to %s: %v", pi.ID, err)
				}
			}
			continue
		}

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
					h.logger.Infof("[Federation] Connected to bootstrap peer: %s via %s", pi.ID, peerStr)
				}
			}
		}
	}
}

// GetAuthenticatedPeers returns the underlying sync.Map containing authenticated peers.
func (h *Hub) GetAuthenticatedPeers() *sync.Map {
	return &h.authenticatedPeers
}
