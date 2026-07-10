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
	"crypto/tls"
	"encoding/hex"
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
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/storage"
	golog "github.com/ipfs/go-log/v2"
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

	// Mint token
	biscuitData, err := identity.MintBiscuitToken(privKey, claims, token, pID, policy)
	if err != nil {
		logger.Errorw("Biscuit minting failed", "peer_id", req.PeerId, "error", err)
		http.Error(w, "Failed to mint biscuit: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Save to DB
	if err := s.store.EnrollNode(ctx, req.PeerId, biscuitData, token.Expiry); err != nil {
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
		{
			Body: []biscuit.Predicate{
				{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(api.RoleBootstrap)}},
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
		PeerID:      req.PeerId,
		Addresses:   req.Addresses,
		LastRenewal: time.Now(),
		ExpiresAt:   expiresAt,
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
