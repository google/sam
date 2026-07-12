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

package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/storage"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v2"
)

var logger = golog.Logger("sam-control-plane")

const (
	EnrollRateLimit        = 10
	EnrollBurst            = 20
	JWTVerificationTimeout = 10 * time.Second
)

// Server implements the SAM Control Plane web app.
type Server struct {
	config     Options
	store      storage.Store
	httpServer *http.Server
	listener   net.Listener
	limiter    *rate.Limiter

	providersMu sync.RWMutex
	providers   map[string]*oidc.Provider

	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	shutdown bool
}

// NewServer initializes the control plane server and stores configuration.
func NewServer(config Options, store storage.Store) (*Server, error) {
	config.Default()
	if err := config.Validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		config:    config,
		store:     store,
		limiter:   rate.NewLimiter(rate.Limit(EnrollRateLimit), EnrollBurst),
		providers: make(map[string]*oidc.Provider),
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

// Start boots up HTTP services, sets up OIDC providers, loads initial keys and policies, and schedules rotations.
func (s *Server) Start() error {
	// Initialize Keyring
	ctx := context.Background()
	_, _, err := s.store.GetCurrentKey(ctx)
	if err == storage.ErrNotFound {
		logger.Info("Generating initial control plane signing keys...")
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate initial key: %w", err)
		}
		if err := s.store.SaveInitialKey(ctx, priv, pub); err != nil {
			return fmt.Errorf("failed to save initial key: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to query initial keyring status: %w", err)
	}

	// Bootstrap Policy from file if DB is empty and path is provided
	if s.config.PolicyPath != "" {
		_, err := s.store.GetPolicy(ctx)
		if err == storage.ErrNotFound {
			logger.Infof("Bootstrapping mesh policy from %s...", s.config.PolicyPath)
			policy, err := loadPolicyFromFile(s.config.PolicyPath)
			if err != nil {
				return fmt.Errorf("failed to load boot policy file: %w", err)
			}
			if err := s.store.SavePolicy(ctx, policy); err != nil {
				return fmt.Errorf("failed to save boot policy: %w", err)
			}
		}
	}

	// Initialize OIDC Providers
	if err := s.discoverProviders(); err != nil {
		return fmt.Errorf("failed OIDC discovery: %w", err)
	}

	// Setup listener
	l, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return err
	}
	s.listener = l

	mux := http.NewServeMux()
	mux.HandleFunc("/info", s.HandleInfo)
	mux.HandleFunc("/register", s.HandleRegister)
	mux.HandleFunc("/keys", s.HandleKeys)
	mux.HandleFunc("/routers/lease", s.HandleRouterLease)
	mux.HandleFunc("/policies", s.HandlePolicies)
	mux.HandleFunc("/enroll", s.HandleEnroll)
	mux.HandleFunc("/enroll/status", s.HandleEnrollStatus)
	mux.HandleFunc("/refresh", s.HandleRefresh)
	mux.HandleFunc("/admin/bootstrap-tokens", s.HandleAdminBootstrapTokens)
	mux.HandleFunc("/admin/enrollments", s.HandleAdminEnrollments)
	mux.HandleFunc("/admin/enrollments/", s.HandleAdminEnrollmentAction)
	mux.HandleFunc("/admin/revoke", s.HandleAdminRevoke)
	mux.HandleFunc("/admin/status", s.HandleAdminStatus)
	mux.HandleFunc("/admin/", s.HandleAdminUI)

	s.httpServer = &http.Server{
		Handler: mux,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		logger.Infof("SAM Control Plane listening on http://%s", s.config.ListenAddr)
		if err := s.httpServer.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Errorf("HTTP Server error: %v", err)
		}
	}()

	// Start key rotation routine
	s.wg.Add(1)
	go s.runKeyRotationLoop()

	return nil
}

func (s *Server) discoverProviders() error {
	s.providersMu.Lock()
	defer s.providersMu.Unlock()

	issuers := strings.Split(s.config.OIDCIssuer, ",")
	for _, iss := range issuers {
		iss = strings.TrimSpace(iss)
		if iss == "" {
			continue
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: s.config.InsecureSkipTLSVerify}
		client := &http.Client{
			Timeout:   30 * time.Second,
			Transport: tr,
		}
		providerCtx := oidc.ClientContext(s.ctx, client)
		provider, err := oidc.NewProvider(providerCtx, iss)
		if err != nil {
			return fmt.Errorf("failed to create provider for %s: %w", iss, err)
		}
		s.providers[iss] = provider
	}
	return nil
}

func (s *Server) getProviders() map[string]*oidc.Provider {
	s.providersMu.RLock()
	defer s.providersMu.RUnlock()

	pCopy := make(map[string]*oidc.Provider)
	for k, v := range s.providers {
		pCopy[k] = v
	}
	return pCopy
}

func (s *Server) runKeyRotationLoop() {
	defer s.wg.Done()
	if s.config.KeyRotationInterval <= 0 {
		return
	}

	ticker := time.NewTicker(s.config.KeyRotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			logger.Info("Rotating Biscuit signing keys...")
			newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				logger.Errorf("Failed to generate key pair for rotation: %v", err)
				continue
			}
			err = s.store.RotateKeys(s.ctx, newPriv, newPub, s.config.KeyGracePeriod)
			if err != nil {
				logger.Errorf("Failed to rotate keyring: %v", err)
			} else {
				logger.Infof("Key rotation committed. New current public key: %s", hex.EncodeToString(newPub))
			}
		case <-s.ctx.Done():
			return
		}
	}
}

// HandleInfo HTTP GET `/info`
func (s *Server) HandleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	issuer := s.config.OIDCIssuer
	if strings.Contains(issuer, ",") {
		parts := strings.Split(issuer, ",")
		issuer = strings.TrimSpace(parts[0])
	}

	aud := api.DefaultAudience
	if len(s.config.AllowedAudiences) > 0 {
		aud = s.config.AllowedAudiences[0]
	}

	// Fetch active routers
	activeRouters, err := s.store.GetActiveRouters(r.Context())
	if err != nil {
		logger.Errorf("Failed to retrieve active routers: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var routerAddrs []string
	for _, r := range activeRouters {
		routerAddrs = append(routerAddrs, r.Addresses...)
	}

	resp := &api.HubInfoResponse{
		OidcIssuer:   issuer,
		ClientId:     aud,
		Audience:     aud,
		HubAddresses: routerAddrs, // Reused this field for back-compatibility with bootstrap routers list
	}

	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

// HandleRegister HTTP POST `/register`
func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var req api.EnrollRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if !s.limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	logger.Infow("New enrollment request", "peer_id", req.PeerId)

	ctx, cancel := context.WithTimeout(r.Context(), JWTVerificationTimeout)
	defer cancel()

	claims, token, err := identity.VerifyJWT(ctx, req.Jwt, s.config.AllowedAudiences, s.getProviders())
	if err != nil {
		logger.Errorw("JWT verification failed", "peer_id", req.PeerId, "error", err)
		http.Error(w, "JWT validation failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	pID, err := peer.Decode(req.PeerId)
	if err != nil {
		http.Error(w, "Invalid Peer ID", http.StatusBadRequest)
		return
	}

	// Fetch mesh policy
	policy, err := s.store.GetPolicy(ctx)
	if err != nil && err != storage.ErrNotFound {
		logger.Errorf("Failed to retrieve mesh policy: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Fetch current signing private key
	privKey, pubKey, err := s.store.GetCurrentKey(ctx)
	if err != nil {
		logger.Errorf("Failed to retrieve current signing key: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if req.RequestedRole == "" {
		http.Error(w, "requested_role must be specified", http.StatusBadRequest)
		return
	}

	// Mint token
	biscuitExpiry := time.Now().Add(api.BiscuitTokenTTL)
	biscuitData, _, err := identity.MintBiscuitToken(privKey, claims, token, pID, policy, biscuitExpiry, req.RequestedRole)
	if err != nil {
		logger.Errorw("Biscuit minting failed", "peer_id", req.PeerId, "error", err)
		http.Error(w, "Failed to mint biscuit: "+err.Error(), http.StatusForbidden)
		return
	}

	// Session TTL is 90 days for OIDC interactive enrollment
	sessionExpiresAt := time.Now().Add(api.OIDCSessionTTL)
	primaryRole := req.RequestedRole

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		logger.Errorf("Failed to marshal OIDC claims: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	nodeRecord := &storage.EnrolledNode{
		PeerID:         req.PeerId,
		PublicKey:      req.PublicKey,
		Biscuit:        biscuitData,
		Role:           primaryRole,
		EnrollmentType: "OIDC",
		ClaimsJSON:     string(claimsBytes),
		EnrolledAt:     time.Now(),
		ExpiresAt:      sessionExpiresAt,
	}

	// Save to DB
	if err := s.store.EnrollNode(ctx, nodeRecord); err != nil {
		logger.Errorf("Failed to persist node enrollment: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Fetch active routers
	activeRouters, err := s.store.GetActiveRouters(ctx)
	if err != nil {
		logger.Errorf("Failed to retrieve active routers: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var routerAddrs []string
	for _, r := range activeRouters {
		routerAddrs = append(routerAddrs, r.Addresses...)
	}

	resp := &api.EnrollResponse{
		BiscuitToken: biscuitData,
		HubPublicKey: pubKey,
		HubAddresses: routerAddrs, // routers nodes multiaddresses
		Expiration:   token.Expiry.Unix(),
	}

	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

// HandleRefresh HTTP POST `/refresh`
func (s *Server) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing current Biscuit token in Authorization header", http.StatusUnauthorized)
		return
	}
	currentBiscuitBase64 := strings.TrimPrefix(authHeader, "Bearer ")
	currentBiscuitBytes, err := base64.StdEncoding.DecodeString(currentBiscuitBase64)
	if err != nil {
		http.Error(w, "Malformed base64 token", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var req api.TokenRefreshRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Fetch all valid signing keys
	validKeys, err := s.store.GetAllValidKeys(ctx)
	if err != nil {
		logger.Errorf("Failed to retrieve valid signing keys: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var trustedKeys []ed25519.PublicKey
	for _, k := range validKeys {
		trustedKeys = append(trustedKeys, k.Public)
	}

	// Verify current biscuit signature and extract peer ID
	pID, err := identity.VerifyAndExtractPeerID(trustedKeys, currentBiscuitBytes)
	if err != nil {
		logger.Warnw("Invalid biscuit presented for refresh", "error", err)
		http.Error(w, "Invalid biscuit: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Fetch node record
	nodeRecord, err := s.store.GetNode(ctx, pID.String())
	if err == storage.ErrNotFound {
		logger.Warnw("Node not found for refresh", "peer_id", pID.String())
		http.Error(w, "Node not enrolled", http.StatusUnauthorized)
		return
	} else if err != nil {
		logger.Errorf("Failed to retrieve node record: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if nodeRecord.Banned {
		logger.Warnw("Banned node attempted refresh", "peer_id", pID.String())
		http.Error(w, "Node is banned", http.StatusForbidden)
		return
	}

	// Check session expiry (OIDC 90 days expiration)
	if !nodeRecord.ExpiresAt.IsZero() && time.Now().After(nodeRecord.ExpiresAt) {
		logger.Warnw("Session expired for node", "peer_id", pID.String(), "expires_at", nodeRecord.ExpiresAt)
		http.Error(w, "Session expired, please re-enroll interactively", http.StatusUnauthorized)
		return
	}

	// Verify challenge signature using stored node public key
	pubKey, err := crypto.UnmarshalPublicKey(nodeRecord.PublicKey)
	if err != nil {
		logger.Errorf("Corrupted public key stored for node %s: %v", nodeRecord.PeerID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	challengeData := []byte(fmt.Sprintf("%d", req.Timestamp))
	ok, err := pubKey.Verify(challengeData, req.ChallengeSignature)
	if err != nil || !ok {
		logger.Warnw("Challenge signature verification failed", "peer_id", nodeRecord.PeerID, "error", err)
		http.Error(w, "Challenge signature verification failed", http.StatusUnauthorized)
		return
	}

	// Fetch current signing private key and policy config
	privKey, _, err := s.store.GetCurrentKey(ctx)
	if err != nil {
		logger.Errorf("Failed to retrieve current signing key: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	policy, err := s.store.GetPolicy(ctx)
	if err != nil && err != storage.ErrNotFound {
		logger.Errorf("Failed to retrieve mesh policy: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var biscuitBytes []byte
	biscuitExpiry := time.Now().Add(api.BiscuitTokenTTL)

	if nodeRecord.EnrollmentType == "OIDC" {
		var claims jwt.MapClaims
		if err := json.Unmarshal([]byte(nodeRecord.ClaimsJSON), &claims); err != nil {
			logger.Errorf("Failed to unmarshal OIDC claims for node %s: %v", nodeRecord.PeerID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		bBytes, _, err := identity.MintBiscuitToken(privKey, claims, nil, pID, policy, biscuitExpiry, nodeRecord.Role)
		if err != nil {
			logger.Errorf("Failed to mint refreshed token for node %s: %v", nodeRecord.PeerID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		biscuitBytes = bBytes
	} else {
		// Bootstrap node
		bBytes, err := identity.MintBootstrapBiscuitToken(privKey, pID, nodeRecord.Role, biscuitExpiry, policy)
		if err != nil {
			logger.Errorf("Failed to mint refreshed token for node %s: %v", nodeRecord.PeerID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		biscuitBytes = bBytes
	}

	// Update node record with new biscuit token
	nodeRecord.Biscuit = biscuitBytes
	nodeRecord.EnrolledAt = time.Now()
	if err := s.store.EnrollNode(ctx, nodeRecord); err != nil {
		logger.Errorf("Failed to persist node refresh: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Write response
	resp := &api.TokenRefreshResponse{
		BiscuitToken: biscuitBytes,
		ExpiresAt:    biscuitExpiry.Unix(),
	}

	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

// HandleKeys HTTP GET `/keys`
func (s *Server) HandleKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	validKeys, err := s.store.GetAllValidKeys(r.Context())
	if err != nil {
		logger.Errorf("Failed to retrieve valid keys: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var pubKeys [][]byte
	for _, k := range validKeys {
		pubKeys = append(pubKeys, k.Public)
	}

	resp := &api.KeysResponse{
		PublicKeys: pubKeys,
	}

	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

// HandleRouterLease HTTP POST `/routers/lease`
func (s *Server) HandleRouterLease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var req api.RouterLeaseRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	pID, err := peer.Decode(req.PeerId)
	if err != nil {
		http.Error(w, "Invalid Peer ID", http.StatusBadRequest)
		return
	}

	// Fetch all valid public keys from CP to authorize router biscuit
	validKeys, err := s.store.GetAllValidKeys(r.Context())
	if err != nil {
		logger.Errorf("Failed to retrieve valid keys: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var cpPubKeys []ed25519.PublicKey
	for _, k := range validKeys {
		cpPubKeys = append(cpPubKeys, k.Public)
	}

	// Verify Biscuit and enforce expected remote peer id
	b, err := identity.VerifyBiscuit(req.Biscuit, pID, cpPubKeys, s.config.BiscuitTimeout)
	if err != nil {
		logger.Warnf("Router %s failed biscuit verification: %v", req.PeerId, err)
		http.Error(w, "Biscuit verification failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Enforce role("router") or role("bootstrap") inside the biscuit
	authorizer, err := b.Authorizer(cpPubKeys[0]) // First public key is generally the current one, but biscuit-go handles matches internally
	if err != nil {
		http.Error(w, "Internal authorizer error", http.StatusInternalServerError)
		return
	}

	authorizer.AddCheck(biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(api.RoleRouter)}},
			},
		},
	}})
	authorizer.AddPolicy(api.AllowIfTruePolicy)

	if err := authorizer.Authorize(); err != nil {
		logger.Warnf("Router %s lacks router role in its biscuit: %v", req.PeerId, err)
		http.Error(w, "Unauthorized: entity is not a router", http.StatusForbidden)
		return
	}

	// Expose lease renewal
	expiresAt := time.Now().Add(s.config.LeaseDuration)
	lease := &storage.RouterLease{
		PeerID:         req.PeerId,
		Addresses:      req.Addresses,
		LastRenewal:    time.Now(),
		ExpiresAt:      expiresAt,
		ConnectedPeers: req.ConnectedPeers,
		DHTSize:        int(req.DhtSize),
	}

	if err := s.store.UpsertRouterLease(r.Context(), lease); err != nil {
		logger.Errorf("Failed to upsert router lease: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	resp := &api.RouterLeaseResponse{
		Success:   true,
		ExpiresAt: expiresAt.Unix(),
	}

	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

// HandlePolicies HTTP GET/POST/PUT `/policies`
func (s *Server) HandlePolicies(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}
	// Simple HTTP admin methods for policies
	switch r.Method {
	case http.MethodGet:
		policy, err := s.store.GetPolicy(r.Context())
		if err == storage.ErrNotFound {
			http.Error(w, "No policy configured", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Errorf("Failed to load policy: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		yamlData, err := yaml.Marshal(policy)
		if err != nil {
			http.Error(w, "Failed to marshal yaml", http.StatusInternalServerError)
			return
		}

		resp := &api.PolicyConfigGetResponse{YamlContent: string(yamlData)}
		respData, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respData)

	case http.MethodPost, http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		defer func() { _ = r.Body.Close() }()

		var req api.PolicyConfigUpdateRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		var policy api.PolicyConfig
		if err := yaml.Unmarshal([]byte(req.YamlContent), &policy); err != nil {
			http.Error(w, "Invalid YAML policy format: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Run validation similar to Hub config loading
		if err := ValidatePolicyConfig(&policy); err != nil {
			http.Error(w, "Invalid policy structure: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := s.store.SavePolicy(r.Context(), &policy); err != nil {
			logger.Errorf("Failed to save policy: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		resp := &api.PolicyConfigUpdateResponse{Success: true}
		respData, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respData)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Close shuts down background loops and HTTP server.
func (s *Server) Close() error {
	s.shutdown = true
	s.cancel()

	var errs []error
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(context.Background()); err != nil {
			errs = append(errs, err)
		}
	}
	s.wg.Wait()
	return errors.Join(errs...)
}

func loadPolicyFromFile(path string) (*api.PolicyConfig, error) {
	// Reused load script from config.go
	return LoadPolicyConfig(path)
}

// Addr returns the network address the server is listening on.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func cryptoRandUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (s *Server) writeEnrollResponse(w http.ResponseWriter, resp *api.BootstrapEnrollResponse) {
	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

func (s *Server) writeEnrollError(w http.ResponseWriter, status api.EnrollmentStatus, errMsg string) {
	s.writeEnrollResponse(w, &api.BootstrapEnrollResponse{
		Status:       status,
		ErrorMessage: errMsg,
	})
}

// HandleEnroll HTTP POST `/enroll`
func (s *Server) HandleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var req api.BootstrapEnrollRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if !s.limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	ctx := r.Context()
	tokenID := fmt.Sprintf("%x", sha256.Sum256([]byte(req.BootstrapToken)))

	// 1. Get and validate bootstrap token
	tokenRecord, err := s.store.GetBootstrapToken(ctx, tokenID)
	if err == storage.ErrNotFound {
		logger.Errorw("Invalid bootstrap token attempt", "peer_id", req.PeerId)
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "Invalid bootstrap token")
		return
	} else if err != nil {
		logger.Errorf("Failed to retrieve bootstrap token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if time.Now().After(tokenRecord.ExpiresAt) {
		logger.Warnw("Expired bootstrap token used", "peer_id", req.PeerId, "token_id", tokenRecord.ID)
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "Bootstrap token expired")
		return
	}

	if tokenRecord.UsagesCount >= tokenRecord.MaxUsages {
		logger.Warnw("Max usages exceeded for bootstrap token", "peer_id", req.PeerId, "token_id", tokenRecord.ID)
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "Bootstrap token max usages exceeded")
		return
	}

	if req.RequestedRole == "" {
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "requested_role must be specified")
		return
	}

	if req.RequestedRole != tokenRecord.Role {
		logger.Warnw("Requested role does not match bootstrap token role", "peer_id", req.PeerId, "requested", req.RequestedRole, "token_role", tokenRecord.Role)
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, fmt.Sprintf("requested role %q does not match bootstrap token role %q", req.RequestedRole, tokenRecord.Role))
		return
	}

	pID, err := peer.Decode(req.PeerId)
	if err != nil {
		http.Error(w, "Invalid Peer ID", http.StatusBadRequest)
		return
	}

	// 2. Check for existing enrollment request
	existingReq, err := s.store.GetEnrollmentRequest(ctx, req.PeerId)
	if err == nil {
		// Request already exists, return status
		var resp *api.BootstrapEnrollResponse
		if existingReq.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
			resp, err = s.buildApprovedBootstrapEnrollResponse(ctx, existingReq.BiscuitToken, existingReq.ResolvedAt)
			if err != nil {
				logger.Errorf("Failed to build approved response: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		} else {
			resp = &api.BootstrapEnrollResponse{
				Status:       existingReq.Status,
				BiscuitToken: existingReq.BiscuitToken,
			}
		}
		s.writeEnrollResponse(w, resp)
		return
	} else if err != storage.ErrNotFound {
		logger.Errorf("Failed to query enrollment request: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 3. Create new enrollment request
	enrollReq := &storage.EnrollmentRequest{
		ID:        cryptoRandUUID(),
		PeerID:    req.PeerId,
		PublicKey: req.PublicKey,
		TokenID:   tokenRecord.ID,
		Status:    api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING,
		CreatedAt: time.Now(),
	}

	// Fetch mesh policy
	policy, err := s.store.GetPolicy(ctx)
	if err != nil && err != storage.ErrNotFound {
		logger.Errorf("Failed to retrieve policy: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Fetch current signing private key
	privKey, _, err := s.store.GetCurrentKey(ctx)
	if err != nil {
		logger.Errorf("Failed to retrieve signing key: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if s.config.AutoApproveEnrollment {
		// Mode A: Auto-Approve
		biscuitBytes, err := identity.MintBootstrapBiscuitToken(privKey, pID, tokenRecord.Role, time.Now().Add(api.BiscuitTokenTTL), policy)
		if err != nil {
			logger.Errorf("Failed to mint bootstrap biscuit: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		enrollReq.Status = api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED
		enrollReq.BiscuitToken = biscuitBytes
		tNow := time.Now()
		enrollReq.ResolvedAt = &tNow
		enrollReq.ResolvedBy = "auto-approver"

		if err := s.store.CreateEnrollmentRequest(ctx, enrollReq); err != nil {
			logger.Errorf("Failed to save enrollment request: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		nodeRecord := &storage.EnrolledNode{
			PeerID:         req.PeerId,
			PublicKey:      req.PublicKey,
			Biscuit:        biscuitBytes,
			Role:           tokenRecord.Role,
			EnrollmentType: "BOOTSTRAP",
			EnrolledAt:     time.Now(),
			ExpiresAt:      time.Time{},
		}
		if err := s.store.EnrollNode(ctx, nodeRecord); err != nil {
			logger.Errorf("Failed to enroll active bootstrap node: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if err := s.store.IncrementBootstrapTokenUsage(ctx, tokenRecord.ID); err != nil {
			logger.Errorf("Failed to increment token usage: %v", err)
		}

		resp, err := s.buildApprovedBootstrapEnrollResponse(ctx, biscuitBytes, enrollReq.ResolvedAt)
		if err != nil {
			logger.Errorf("Failed to build approved response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		s.writeEnrollResponse(w, resp)
		return
	}

	// Mode B: Manual approval queue
	if err := s.store.CreateEnrollmentRequest(ctx, enrollReq); err != nil {
		logger.Errorf("Failed to save pending enrollment request: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	resp := &api.BootstrapEnrollResponse{
		Status:              api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING,
		PollIntervalSeconds: 30,
	}
	s.writeEnrollResponse(w, resp)
}

// HandleEnrollStatus HTTP GET `/enroll/status`
func (s *Server) HandleEnrollStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	peerID := r.URL.Query().Get("peer_id")
	if peerID == "" {
		http.Error(w, "Missing peer_id parameter", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	enrollReq, err := s.store.GetEnrollmentRequest(ctx, peerID)
	if err == storage.ErrNotFound {
		s.writeEnrollError(w, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, "Enrollment request not found")
		return
	} else if err != nil {
		logger.Errorf("Failed to retrieve enrollment status: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var resp *api.BootstrapEnrollResponse
	if enrollReq.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
		resp, err = s.buildApprovedBootstrapEnrollResponse(ctx, enrollReq.BiscuitToken, enrollReq.ResolvedAt)
		if err != nil {
			logger.Errorf("Failed to build approved response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	} else {
		resp = &api.BootstrapEnrollResponse{
			Status:       enrollReq.Status,
			BiscuitToken: enrollReq.BiscuitToken,
		}
		if enrollReq.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
			resp.PollIntervalSeconds = 30
		}
	}
	s.writeEnrollResponse(w, resp)
}

func (s *Server) checkAdminAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.config.AdminToken == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" || token != s.config.AdminToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// HandleAdminBootstrapTokens HTTP POST `/admin/bootstrap-tokens`
func (s *Server) HandleAdminBootstrapTokens(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Role        string `json:"role"`
		TTLHours    int    `json:"ttl_hours"`
		MaxUsages   int    `json:"max_usages"`
		Description string `json:"description"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	if req.Role == "" {
		req.Role = api.RoleRouter
	}
	if req.TTLHours <= 0 {
		req.TTLHours = 24
	}
	if req.MaxUsages <= 0 {
		req.MaxUsages = 1
	}

	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		http.Error(w, "Internal keygen error", http.StatusInternalServerError)
		return
	}
	tokenVal := fmt.Sprintf("sam-bt-%x", randBytes)
	tokenID := fmt.Sprintf("%x", sha256.Sum256([]byte(tokenVal)))

	tokenRecord := &storage.BootstrapToken{
		ID:          tokenID,
		TokenHash:   tokenID,
		Role:        req.Role,
		MaxUsages:   req.MaxUsages,
		UsagesCount: 0,
		Description: req.Description,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(time.Duration(req.TTLHours) * time.Hour),
	}

	if err := s.store.SaveBootstrapToken(r.Context(), tokenRecord); err != nil {
		logger.Errorf("Failed to save bootstrap token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":         tokenRecord.ID,
		"token":      tokenVal,
		"role":       tokenRecord.Role,
		"expires_at": tokenRecord.ExpiresAt.Format(time.RFC3339),
	})
}

// HandleAdminEnrollments HTTP GET `/admin/enrollments`
func (s *Server) HandleAdminEnrollments(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	list, err := s.store.ListEnrollmentRequests(r.Context())
	if err != nil {
		logger.Errorf("Failed to list enrollment requests: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(list)
}

// HandleAdminEnrollmentAction HTTP POST `/admin/enrollments/{id}/approve` or `/admin/enrollments/{id}/reject`
func (s *Server) HandleAdminEnrollmentAction(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/admin/enrollments/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	id := parts[0]
	action := parts[1]

	ctx := r.Context()
	enrollReq, err := s.store.GetEnrollmentRequestByID(ctx, id)
	if err == storage.ErrNotFound {
		http.Error(w, "Enrollment request not found", http.StatusNotFound)
		return
	} else if err != nil {
		logger.Errorf("Failed to query enrollment request: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if enrollReq.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
		http.Error(w, "Enrollment request is already resolved", http.StatusConflict)
		return
	}

	adminIdentity := "admin"

	if action == "reject" {
		err = s.store.UpdateEnrollmentRequest(ctx, id, api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, nil, adminIdentity)
		if err != nil {
			logger.Errorf("Failed to reject enrollment: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Enrollment rejected"))
		return
	}

	if action == "approve" {
		tokenRecord, err := s.store.GetBootstrapToken(ctx, enrollReq.TokenID)
		if err != nil {
			logger.Errorf("Failed to retrieve token for request: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		pID, err := peer.Decode(enrollReq.PeerID)
		if err != nil {
			http.Error(w, "Invalid Peer ID stored in request", http.StatusInternalServerError)
			return
		}

		policy, err := s.store.GetPolicy(ctx)
		if err != nil && err != storage.ErrNotFound {
			logger.Errorf("Failed to retrieve policy: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		privKey, _, err := s.store.GetCurrentKey(ctx)
		if err != nil {
			logger.Errorf("Failed to retrieve signing key: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		biscuitBytes, err := identity.MintBootstrapBiscuitToken(privKey, pID, tokenRecord.Role, time.Now().Add(api.BiscuitTokenTTL), policy)
		if err != nil {
			logger.Errorf("Failed to mint bootstrap biscuit: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		err = s.store.UpdateEnrollmentRequest(ctx, id, api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED, biscuitBytes, adminIdentity)
		if err != nil {
			logger.Errorf("Failed to approve enrollment request in DB: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		nodeRecord := &storage.EnrolledNode{
			PeerID:         enrollReq.PeerID,
			PublicKey:      enrollReq.PublicKey,
			Biscuit:        biscuitBytes,
			Role:           tokenRecord.Role,
			EnrollmentType: "BOOTSTRAP",
			EnrolledAt:     time.Now(),
			ExpiresAt:      time.Time{},
		}
		if err := s.store.EnrollNode(ctx, nodeRecord); err != nil {
			logger.Errorf("Failed to enroll active bootstrap node: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if err := s.store.IncrementBootstrapTokenUsage(ctx, tokenRecord.ID); err != nil {
			logger.Errorf("Failed to increment token usage: %v", err)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Enrollment approved"))
		return
	}

	http.Error(w, "Invalid action", http.StatusBadRequest)
}

// HandleAdminRevoke HTTP POST `/admin/revoke`
func (s *Server) HandleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var req api.TokenRevokeRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if req.PeerId == "" {
		http.Error(w, "peer_id is required", http.StatusBadRequest)
		return
	}

	// Retrieve the node from storage to verify it exists
	_, err = s.store.GetNode(ctx, req.PeerId)
	if err == storage.ErrNotFound {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	} else if err != nil {
		logger.Errorf("Failed to retrieve node record for revocation: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set node as banned (revoked)
	if err := s.store.SetNodeBanned(ctx, req.PeerId, true); err != nil {
		logger.Errorf("Failed to ban/revoke node %s: %v", req.PeerId, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	resp := &api.TokenRevokeResponse{
		Success: true,
	}
	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

func (s *Server) buildApprovedBootstrapEnrollResponse(ctx context.Context, biscuitToken []byte, resolvedAt *time.Time) (*api.BootstrapEnrollResponse, error) {
	_, pubKey, err := s.store.GetCurrentKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve signing key: %w", err)
	}

	activeRouters, err := s.store.GetActiveRouters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve active routers: %w", err)
	}

	var routerAddrs []string
	for _, r := range activeRouters {
		routerAddrs = append(routerAddrs, r.Addresses...)
	}

	expiration := time.Now().Add(api.BiscuitTokenTTL).Unix()
	if resolvedAt != nil {
		expiration = resolvedAt.Add(api.BiscuitTokenTTL).Unix()
	}

	return &api.BootstrapEnrollResponse{
		Status:       api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED,
		BiscuitToken: biscuitToken,
		HubPublicKey: pubKey,
		HubAddresses: routerAddrs,
		Expiration:   expiration,
	}, nil
}
