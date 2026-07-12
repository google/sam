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

package router

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	records "github.com/libp2p/go-libp2p-kad-dht/records"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	"google.golang.org/protobuf/proto"
)

var logger = golog.Logger("sam-router")

const (
	LowWaterMark    = 100
	HighWaterMark   = 400
	ConnGracePeriod = 1 * time.Minute
)

type relayACL struct {
	r *Router
}

func (a *relayACL) AllowReserve(p peer.ID, addr multiaddr.Multiaddr) bool {
	_, ok := a.r.authenticatedPeers.Load(p)
	if !ok {
		logger.Debugf("[Relay] Rejecting reservation for %s: not authenticated", p)
	}
	return ok
}

func (a *relayACL) AllowConnect(src peer.ID, srcAddr multiaddr.Multiaddr, dest peer.ID) bool {
	_, ok := a.r.authenticatedPeers.Load(dest)
	if !ok {
		logger.Debugf("[Relay] Rejecting connect from %s to %s: dest not authenticated", src, dest)
	}
	return ok
}

// Router represents a libp2p bootstrap/relay node.
type Router struct {
	config             Options
	Host               host.Host
	DHT                *dht.IpfsDHT
	PubSub             *pubsub.PubSub
	EventTopic         *pubsub.Topic
	authenticatedPeers sync.Map

	// Keys & Identity
	biscuitToken      []byte
	biscuitExpiration time.Time
	trustedPublicKeys []ed25519.PublicKey
	keysMu            sync.RWMutex
	privKey           crypto.PrivKey

	// Control contexts
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	isReady  atomic.Bool
	shutdown bool
}

// NewRouter initializes the router.
func NewRouter(ctx context.Context, config Options) (*Router, error) {
	config.Default()
	if err := config.Validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)

	return &Router{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Start performs enrollment, syncs keys, launches libp2p host, and starts tasks.
func (r *Router) Start() error {
	// 1. Load or Generate persistent identity key
	priv, err := getOrGeneratePeerKey(r.config.KeysDBPath)
	if err != nil {
		return fmt.Errorf("failed to load/generate peer identity: %w", err)
	}
	r.privKey = priv

	peerID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return err
	}

	if r.config.BootstrapToken == "" && r.config.BootstrapTokenPath != "" {
		tokenData, err := os.ReadFile(r.config.BootstrapTokenPath)
		if err != nil {
			return fmt.Errorf("failed to read bootstrap token from path %s: %w", r.config.BootstrapTokenPath, err)
		}
		r.config.BootstrapToken = strings.TrimSpace(string(tokenData))
	}

	if r.config.BootstrapToken != "" {
		logger.Infof("Enrolling router %s with Control Plane at %s using Bootstrap Token...", peerID, r.config.ControlPlaneURL)
		if err := r.enrollBootstrap(peerID); err != nil {
			return fmt.Errorf("failed router bootstrap enrollment: %w", err)
		}
	} else {
		if r.config.OIDCToken == "" && r.config.JWTPath != "" {
			tokenData, err := os.ReadFile(r.config.JWTPath)
			if err != nil {
				return fmt.Errorf("failed to read JWT from path %s: %w", r.config.JWTPath, err)
			}
			r.config.OIDCToken = strings.TrimSpace(string(tokenData))
		}

		if r.config.OIDCToken != "" {
			logger.Infof("Enrolling router %s with Control Plane at %s using OIDC Token...", peerID, r.config.ControlPlaneURL)
			if err := r.enroll(peerID); err != nil {
				return fmt.Errorf("failed router enrollment: %w", err)
			}
		} else {
			logger.Warn("Router started without OIDCToken or BootstrapToken. Enrollment bypassed. Expecting local keys sync.")
		}
	}

	// 3. Initial Keys Sync
	if err := r.syncKeys(); err != nil {
		return fmt.Errorf("failed initial keys sync: %w", err)
	}

	// 4. Initialize libp2p host
	cm, err := connmgr.NewConnManager(LowWaterMark, HighWaterMark, connmgr.WithGracePeriod(ConnGracePeriod))
	if err != nil {
		return fmt.Errorf("failed to create connection manager: %w", err)
	}

	p2pOpts := []libp2p.Option{
		libp2p.Identity(r.privKey),
		libp2p.DefaultTransports,
		libp2p.ListenAddrStrings(r.config.ListenAddrs...),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.ConnectionManager(cm),
		libp2p.EnableAutoNATv2(),
		libp2p.EnableNATService(),
		libp2p.AddrsFactory(func(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			if r.config.AllowLoopback {
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
	r.Host = hostNode

	// Setup DHT
	dhtOpts := []dht.Option{
		dht.Mode(dht.ModeServer),
		dht.ProtocolPrefix("/sam"),
	}
	var pmOpts []records.Option
	if r.config.DHTProviderAddrTTL > 0 {
		pmOpts = append(pmOpts, records.ProviderAddrTTL(r.config.DHTProviderAddrTTL))
		pmOpts = append(pmOpts, records.ProvideValidity(r.config.DHTProviderAddrTTL))
	}
	if len(pmOpts) > 0 {
		dhtOpts = append(dhtOpts, dht.ProviderManagerOpts(pmOpts...))
	}
	if r.config.DHTMaxRecordAge > 0 {
		dhtOpts = append(dhtOpts, dht.MaxRecordAge(r.config.DHTMaxRecordAge))
	}
	kadDHT, err := dht.New(r.ctx, hostNode, dhtOpts...)
	if err != nil {
		_ = hostNode.Close()
		return err
	}
	r.DHT = kadDHT

	if err = kadDHT.Bootstrap(r.ctx); err != nil {
		_ = hostNode.Close()
		return err
	}

	// Setup Relay
	_, err = relay.New(hostNode, relay.WithACL(&relayACL{r: r}))
	if err != nil {
		_ = hostNode.Close()
		return err
	}

	// Setup PubSub
	ps, err := pubsub.NewGossipSub(r.ctx, hostNode)
	if err != nil {
		_ = hostNode.Close()
		return err
	}
	r.PubSub = ps

	topic, err := ps.Join(api.GossipEvents)
	if err != nil {
		_ = hostNode.Close()
		return err
	}
	r.EventTopic = topic

	// Setup authentication stream handler
	hostNode.SetStreamHandler(api.AuthProtocolID, r.HandleAuthHandshake)

	// Clean authenticated status on peer disconnection
	hostNode.Network().Notify(&network.NotifyBundle{
		DisconnectedF: func(n network.Network, c network.Conn) {
			p := c.RemotePeer()
			if len(hostNode.Network().ConnsToPeer(p)) == 0 {
				r.authenticatedPeers.Delete(p)
			}
		},
	})

	// 5. Start background routines
	r.wg.Add(4)
	go r.runLeaseRenewalLoop()
	go r.runKeysSyncLoop()
	go r.runFederationLoop()
	go r.runBiscuitRenewalLoop()

	r.isReady.Store(true)
	logger.Infof("Router Online. PeerID: %s, ListenAddrs: %v", r.Host.ID(), r.Host.Addrs())
	return nil
}

func (r *Router) enroll(peerID peer.ID) error {
	pubKey := r.privKey.GetPublic()
	pubBytes, err := crypto.MarshalPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	req := &api.EnrollRequest{
		Jwt:           r.config.OIDCToken,
		PeerId:        peerID.String(),
		PublicKey:     pubBytes,
		RequestedRole: r.config.RequiredRole,
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(r.config.ControlPlaneURL+"/register", "application/x-protobuf", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enrollment response status %s: %s", resp.Status, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var enrollResp api.EnrollResponse
	if err := proto.Unmarshal(body, &enrollResp); err != nil {
		return err
	}

	r.biscuitToken = enrollResp.BiscuitToken
	r.biscuitExpiration = time.Unix(enrollResp.Expiration, 0)
	r.keysMu.Lock()
	r.trustedPublicKeys = []ed25519.PublicKey{enrollResp.HubPublicKey}
	r.keysMu.Unlock()

	if err := identity.VerifyBiscuitRole(enrollResp.BiscuitToken, enrollResp.HubPublicKey, r.config.RequiredRole); err != nil {
		return fmt.Errorf("enrolled biscuit token lacks required role %q: %w", r.config.RequiredRole, err)
	}

	return nil
}

func (r *Router) enrollBootstrap(peerID peer.ID) error {
	pubKey := r.privKey.GetPublic()
	pubBytes, err := crypto.MarshalPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal router public key: %w", err)
	}

	req := &api.BootstrapEnrollRequest{
		BootstrapToken: r.config.BootstrapToken,
		PeerId:         peerID.String(),
		PublicKey:      pubBytes,
		RequestedRole:  r.config.RequiredRole,
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(r.config.ControlPlaneURL+"/enroll", "application/x-protobuf", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bootstrap enrollment request response status %s: %s", resp.Status, string(body))
	}

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	enrollResp := &api.BootstrapEnrollResponse{}
	if err := proto.Unmarshal(respData, enrollResp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if enrollResp.ErrorMessage != "" {
		return fmt.Errorf("enrollment failed: %s", enrollResp.ErrorMessage)
	}

	if enrollResp.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
		logger.Infof("Enrollment is pending approval. Polling status...")
		statusReq := &api.EnrollmentStatusRequest{
			PeerId: peerID.String(),
		}
		statusData, err := proto.Marshal(statusReq)
		if err != nil {
			return fmt.Errorf("failed to marshal status request: %w", err)
		}

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

	pollLoop:
		for {
			select {
			case <-r.ctx.Done():
				return r.ctx.Err()
			case <-ticker.C:
				statusResp, err := client.Post(r.config.ControlPlaneURL+"/enroll/status", "application/x-protobuf", bytes.NewReader(statusData))
				if err != nil {
					logger.Warnf("failed to poll enrollment status: %v", err)
					continue
				}

				if statusResp.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(statusResp.Body)
					_ = statusResp.Body.Close()
					logger.Warnf("status poll returned code %s: %s", statusResp.Status, string(body))
					continue
				}

				statusBody, err := io.ReadAll(statusResp.Body)
				_ = statusResp.Body.Close()
				if err != nil {
					logger.Warnf("failed to read status body: %v", err)
					continue
				}

				pollResp := &api.BootstrapEnrollResponse{}
				if err := proto.Unmarshal(statusBody, pollResp); err != nil {
					logger.Warnf("failed to unmarshal poll response: %v", err)
					continue
				}

				if pollResp.ErrorMessage != "" {
					return fmt.Errorf("enrollment rejected: %s", pollResp.ErrorMessage)
				}

				if pollResp.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
					enrollResp = pollResp
					break pollLoop
				}
				if pollResp.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
					return fmt.Errorf("enrollment rejected by administrator")
				}
				logger.Infof("Enrollment is still pending approval...")
			}
		}
	}

	if enrollResp.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
		return fmt.Errorf("enrollment not approved (status: %v)", enrollResp.Status)
	}

	r.biscuitToken = enrollResp.BiscuitToken
	r.biscuitExpiration = time.Unix(enrollResp.Expiration, 0)
	r.keysMu.Lock()
	r.trustedPublicKeys = []ed25519.PublicKey{enrollResp.HubPublicKey}
	r.keysMu.Unlock()

	if err := identity.VerifyBiscuitRole(enrollResp.BiscuitToken, enrollResp.HubPublicKey, r.config.RequiredRole); err != nil {
		return fmt.Errorf("enrolled biscuit token lacks required role %q: %w", r.config.RequiredRole, err)
	}

	logger.Infof("Router bootstrap enrollment approved! Biscuit received.")
	return nil
}

func (r *Router) syncKeys() error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(r.config.ControlPlaneURL + "/keys")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to sync keys, status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var keysResp api.KeysResponse
	if err := proto.Unmarshal(body, &keysResp); err != nil {
		return err
	}

	r.keysMu.Lock()
	var newKeys []ed25519.PublicKey
	for _, kb := range keysResp.PublicKeys {
		if len(kb) == ed25519.PublicKeySize {
			newKeys = append(newKeys, ed25519.PublicKey(kb))
		}
	}
	r.trustedPublicKeys = newKeys
	r.keysMu.Unlock()

	logger.Debugf("Synced %d valid public keys from control plane", len(newKeys))
	return nil
}

func (r *Router) getTrustedPublicKeys() []ed25519.PublicKey {
	r.keysMu.RLock()
	defer r.keysMu.RUnlock()
	return append([]ed25519.PublicKey(nil), r.trustedPublicKeys...)
}

func (r *Router) runKeysSyncLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.config.KeysSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := r.syncKeys(); err != nil {
				logger.Errorf("Failed periodic keys sync: %v", err)
			}
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *Router) runLeaseRenewalLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.config.LeaseRenewInterval)
	defer ticker.Stop()

	// Initial renewal after host is online
	r.renewLease()

	for {
		select {
		case <-ticker.C:
			r.renewLease()
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *Router) renewLease() {
	if len(r.biscuitToken) == 0 {
		logger.Warn("Cannot renew lease: router is not enrolled (no biscuit)")
		return
	}

	var addrs []string
	if len(r.config.ExternalAddrs) > 0 {
		for _, addr := range r.config.ExternalAddrs {
			addrs = append(addrs, addr+"/p2p/"+r.Host.ID().String())
		}
	} else {
		for _, addr := range r.Host.Addrs() {
			addrs = append(addrs, addr.String()+"/p2p/"+r.Host.ID().String())
		}
	}

	var connectedPeers []string
	if r.Host != nil && r.Host.Network() != nil {
		for _, p := range r.Host.Network().Peers() {
			connectedPeers = append(connectedPeers, p.String())
		}
	}
	var dhtSize int32
	if r.DHT != nil && r.DHT.RoutingTable() != nil {
		dhtSize = int32(r.DHT.RoutingTable().Size())
	}

	req := &api.RouterLeaseRequest{
		PeerId:         r.Host.ID().String(),
		Addresses:      addrs,
		Biscuit:        r.biscuitToken,
		ConnectedPeers: connectedPeers,
		DhtSize:        dhtSize,
	}
	data, _ := proto.Marshal(req)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(r.config.ControlPlaneURL+"/routers/lease", "application/x-protobuf", bytes.NewReader(data))
	if err != nil {
		logger.Errorf("Failed to renew lease with control plane: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.Errorf("Control plane lease renewal rejected, status %s: %s", resp.Status, string(body))
		return
	}

	var leaseResp api.RouterLeaseResponse
	body, _ := io.ReadAll(resp.Body)
	if err := proto.Unmarshal(body, &leaseResp); err != nil {
		logger.Errorf("Failed to parse lease response: %v", err)
		return
	}

	if !leaseResp.Success {
		logger.Errorf("Lease renewal failed: %s", leaseResp.Error)
	} else {
		logger.Debugf("Lease renewed successfully. Expires at: %s", time.Unix(leaseResp.ExpiresAt, 0))
	}
}

func (r *Router) runFederationLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	r.connectBootstrapRouters()

	for {
		select {
		case <-ticker.C:
			r.connectBootstrapRouters()
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *Router) connectBootstrapRouters() {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(r.config.ControlPlaneURL + "/info")
	if err != nil {
		logger.Errorf("[Federation] Failed to fetch router info: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		logger.Errorf("[Federation] GET /info returned status %d", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var info api.HubInfoResponse
	if err := proto.Unmarshal(body, &info); err != nil {
		return
	}

	for _, addrStr := range info.HubAddresses {
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			continue
		}

		resolvedAddrs, err := madns.DefaultResolver.Resolve(r.ctx, ma)
		if err != nil {
			resolvedAddrs = []multiaddr.Multiaddr{ma}
		}

		for _, resolved := range resolvedAddrs {
			pi, err := peer.AddrInfoFromP2pAddr(resolved)
			if err != nil || pi.ID == r.Host.ID() {
				continue
			}

			if len(r.Host.Network().ConnsToPeer(pi.ID)) == 0 {
				logger.Infof("[Federation] Connecting to peer router: %s via %s", pi.ID, resolved)
				// Create a timeout context
				connectCtx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
				if err := r.Host.Connect(connectCtx, *pi); err == nil {
					// Initiate stream to perform mutual auth handshake
					s, err := r.Host.NewStream(connectCtx, pi.ID, api.AuthProtocolID)
					if err == nil {
						if err := r.performMutualAuth(s); err != nil {
							logger.Errorf("[Federation] Mutual auth handshake failed with %s: %v", pi.ID, err)
							_ = s.Reset()
						} else {
							logger.Infof("[Federation] Mutually authenticated with peer router %s", pi.ID)
							_ = s.Close()
						}
					} else {
						logger.Errorf("[Federation] Failed to open auth stream to %s: %v", pi.ID, err)
					}
				} else {
					logger.Errorf("[Federation] Failed to connect to %s: %v", pi.ID, err)
				}
				cancel()
			}
		}
	}
}

// HandleAuthHandshake processes incoming auth connections.
// It is part of mutual auth:
// 1. Receives client's Biscuit.
// 2. Verifies it against CP public keys.
// 3. Responds with success and the router's own Biscuit.
func (r *Router) HandleAuthHandshake(s network.Stream) {
	defer func() { _ = s.Close() }()
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

	// Verify Biscuit
	_, err = identity.VerifyBiscuit(exchange.Biscuit, remotePeer, r.getTrustedPublicKeys(), r.config.BiscuitTimeout)
	if err != nil {
		logger.Warnf("[AuthN] Authorization failed for peer %s: %v", remotePeer, err)
		_ = s.Reset()
		return
	}

	r.authenticatedPeers.Store(remotePeer, true)
	logger.Infof("[AuthN] Successfully authenticated peer %s", remotePeer)

	// Send mutual response (our biscuit)
	writer := msgio.NewVarintWriter(s)
	resp := &api.AuthResponse{
		Success: true,
		Biscuit: r.biscuitToken,
	}
	respBytes, _ := proto.Marshal(resp)
	if err := writer.WriteMsg(respBytes); err != nil {
		logger.Errorf("[AuthN] Failed to write mutual ACK to %s: %v", remotePeer, err)
	}
}

// performMutualAuth initiates client-side mutual authentication handshake.
func (r *Router) performMutualAuth(s network.Stream) error {
	remotePeer := s.Conn().RemotePeer()
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))

	// Send our biscuit
	writer := msgio.NewVarintWriter(s)
	authFrame := &api.AuthFrame{Biscuit: r.biscuitToken}
	data, _ := proto.Marshal(authFrame)
	if err := writer.WriteMsg(data); err != nil {
		return fmt.Errorf("write mutual auth frame: %w", err)
	}

	// Read response (success + remote biscuit)
	reader := msgio.NewVarintReaderSize(s, 1024*64)
	respMsg, err := reader.ReadMsg()
	if err != nil {
		return fmt.Errorf("read mutual auth response: %w", err)
	}
	defer reader.ReleaseMsg(respMsg)

	var resp api.AuthResponse
	if err := proto.Unmarshal(respMsg, &resp); err != nil {
		return fmt.Errorf("unmarshal mutual auth response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("mutual auth handshake rejected: %s", resp.Error)
	}

	trustedKeys := r.getTrustedPublicKeys()
	if len(trustedKeys) == 0 {
		return fmt.Errorf("no trusted control plane keys loaded")
	}

	// Verify remote biscuit
	b, err := identity.VerifyBiscuit(resp.Biscuit, remotePeer, trustedKeys, r.config.BiscuitTimeout)
	if err != nil {
		return fmt.Errorf("failed to verify peer router biscuit: %w", err)
	}

	// Enforce required role inside the biscuit
	authorizer, err := b.Authorizer(trustedKeys[0])
	if err != nil {
		return fmt.Errorf("authorizer instantiation failed: %w", err)
	}

	authorizer.AddCheck(biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(r.config.RequiredRole)}},
			},
		},
	}})
	authorizer.AddPolicy(api.AllowIfTruePolicy)

	if err := authorizer.Authorize(); err != nil {
		return fmt.Errorf("remote peer lacks router authorization role: %w", err)
	}

	r.authenticatedPeers.Store(remotePeer, true)
	return nil
}

// Close closes the underlying p2p host and keyring db.
func (r *Router) Close() error {
	r.shutdown = true
	r.cancel()

	var errs []error
	if r.DHT != nil {
		if err := r.DHT.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if r.Host != nil {
		if err := r.Host.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	r.wg.Wait()
	return errors.Join(errs...)
}

func getOrGeneratePeerKey(keyPath string) (crypto.PrivKey, error) {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return nil, err
	}

	if _, err := os.Stat(keyPath); err == nil {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		return crypto.UnmarshalPrivateKey(data)
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return nil, err
	}
	data, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, data, 0600); err != nil {
		return nil, err
	}
	return priv, nil
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

// RefreshEnrollment trades the expiring biscuit token for a new one using a cryptographic challenge.
func (r *Router) RefreshEnrollment(ctx context.Context) error {
	r.keysMu.Lock()
	defer r.keysMu.Unlock()

	if len(r.biscuitToken) == 0 {
		return fmt.Errorf("router not enrolled (no biscuit)")
	}

	// 1. Generate challenge signature over current timestamp
	timestamp := time.Now().UnixMilli()
	challengeData := []byte(fmt.Sprintf("%d", timestamp))
	sig, err := r.privKey.Sign(challengeData)
	if err != nil {
		return fmt.Errorf("failed to generate signature: %w", err)
	}

	// 2. Construct request
	req := &api.TokenRefreshRequest{
		ChallengeSignature: sig,
		Timestamp:          timestamp,
	}
	reqData, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := r.config.ControlPlaneURL + "/refresh"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqData))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	// Set current biscuit in authorization header
	b64Biscuit := base64.StdEncoding.EncodeToString(r.biscuitToken)
	httpReq.Header.Set("Authorization", "Bearer "+b64Biscuit)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusForbidden {
		logger.Errorf("Refresh rejected: Router is banned (403 Forbidden). Hard-killing router.")
		if r.Host != nil {
			_ = r.Host.Close()
		}
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("refresh failed with status %s: %s", resp.Status, string(body))
	}

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var refreshResp api.TokenRefreshResponse
	if err := proto.Unmarshal(respData, &refreshResp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if refreshResp.ErrorMessage != "" {
		return fmt.Errorf("refresh error: %s", refreshResp.ErrorMessage)
	}

	// Update local biscuit token and expiration
	r.biscuitToken = refreshResp.BiscuitToken
	r.biscuitExpiration = time.Unix(refreshResp.ExpiresAt, 0)
	logger.Infof("Router biscuit token refreshed successfully.")
	return nil
}

func (r *Router) runBiscuitRenewalLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(api.TokenRefreshCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.keysMu.RLock()
			expiration := r.biscuitExpiration
			r.keysMu.RUnlock()

			if !expiration.IsZero() && time.Until(expiration) < api.BiscuitTokenTTL/5 { // 80% elapsed lifespan of 24h (remaining time < 20% of TTL)
				logger.Infof("Router biscuit expiring in %v, triggering proactive refresh...", time.Until(expiration))
				if err := r.RefreshEnrollment(r.ctx); err != nil {
					logger.Errorf("Proactive router biscuit refresh failed: %v", err)
				}
			}
		case <-r.ctx.Done():
			return
		}
	}
}
