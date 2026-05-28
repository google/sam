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
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/protobuf/proto"
)

// startHTTPServer starts the HTTP/HTTPS server for metrics, healthz, and admin commands.
func startHTTPServer(h *Hub, bindAddr string, adminToken string, tlsCertFile string, tlsKeyFile string, tlsCAFile string, isHubReady *atomic.Bool) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}))
	mux.HandleFunc("/register", handleRegisterHTTP(h))
	mux.HandleFunc("/info", handleInfoHTTP(h))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if isHubReady.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
		}
	})

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
		Addr:    bindAddr,
		Handler: mux,
	}

	// Configure TLS if requested
	if tlsCertFile != "" && tlsKeyFile != "" {
		tlsConfig := &tls.Config{}
		if tlsCAFile != "" {
			caCert, err := os.ReadFile(tlsCAFile)
			if err != nil {
				logger.Fatalf("Failed to read CA cert: %v", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			logger.Info("mTLS enabled for admin service")
		}
		server.TLSConfig = tlsConfig

		logger.Infof("Starting HTTPS server on %s", bindAddr)
		go func() {
			if err := server.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil && err != http.ErrServerClosed {
				logger.Errorf("HTTPS server failed: %v", err)
			}
		}()
	} else {
		logger.Infof("Starting HTTP server on %s", bindAddr)
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Errorf("HTTP server failed: %v", err)
			}
		}()
	}
}

func handleRegisterHTTP(h *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		defer func() {
			if err := r.Body.Close(); err != nil {
				logger.Errorf("failed to close request body: %v", err)
			}
		}()

		var req api.EnrollRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		if !h.limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		logger.Infow("New HTTP enrollment request", "peer_id", req.PeerId)

		ctx, cancel := context.WithTimeout(context.Background(), JWTVerificationTimeout)
		defer cancel()

		claims, token, err := h.parseAndVerifyJWT(ctx, req.Jwt, h.AllowedAudiences)
		if err != nil {
			logger.Errorw("JWT verification failed", "peer_id", req.PeerId, "error", err)
			http.Error(w, "JWT validation failed: "+err.Error(), http.StatusUnauthorized)
			return
		}

		pID, err := peer.Decode(req.PeerId)
		if err != nil {
			logger.Errorw("Invalid Peer ID", "peer_id", req.PeerId, "error", err)
			http.Error(w, "Invalid Peer ID", http.StatusBadRequest)
			return
		}

		biscuitData, err := h.mintBiscuitToken(claims, token, pID)
		if err != nil {
			logger.Errorw("Biscuit minting failed", "peer_id", req.PeerId, "error", err)
			http.Error(w, "Failed to mint biscuit", http.StatusInternalServerError)
			return
		}

		h.gater.mu.Lock()
		if !h.gater.authenticated[pID] {
			samHubActiveNodes.Inc()
		}
		h.gater.authenticated[pID] = true
		h.gater.mu.Unlock()

		var authPeers []peer.ID
		h.gater.mu.Lock()
		for p := range h.gater.authenticated {
			authPeers = append(authPeers, p)
		}
		h.gater.mu.Unlock()

		var knownPeers []string
		for _, p := range authPeers {
			knownPeers = append(knownPeers, p.String())
		}

		var hubAddrs []string
		if len(h.ExternalAddrs) > 0 {
			for _, addr := range h.ExternalAddrs {
				fullAddr := addr
				if !strings.Contains(addr, "/p2p/") {
					fullAddr = addr + "/p2p/" + h.Host.ID().String()
				}
				hubAddrs = append(hubAddrs, fullAddr)
			}
		} else {
			for _, addr := range h.Host.Addrs() {
				hubAddrs = append(hubAddrs, addr.String()+"/p2p/"+h.Host.ID().String())
			}
		}

		resp := &api.EnrollResponse{
			BiscuitToken: biscuitData,
			HubPublicKey: h.KeyRing.GetCurrentPublicKey(),
			HubAddresses: hubAddrs,
			Expiration:   token.Expiry.Unix(),
			KnownPeers:   knownPeers,
		}

		respData, err := proto.Marshal(resp)
		if err != nil {
			logger.Errorf("[Enroll] Failed to marshal response: %v", err)
			http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respData)

		logger.Infow("Successfully enrolled peer via HTTP", "peer_id", req.PeerId)
		samHubEnrollmentTotal.WithLabelValues("success").Inc()
	}
}

func handleInfoHTTP(h *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Find the OIDC issuer deterministically by sorting the map keys
		issuer := ""
		if len(h.Providers) > 0 {
			issuers := make([]string, 0, len(h.Providers))
			for iss := range h.Providers {
				issuers = append(issuers, iss)
			}
			sort.Strings(issuers)
			issuer = issuers[0]
		}

		// Fallback if Providers isn't fully populated (e.g. in unit tests)
		if issuer == "" {
			issuer = oidcIssuer
		}
		// If multiple issuers in fallback, pick the first one deterministically
		if strings.Contains(issuer, ",") {
			parts := strings.Split(issuer, ",")
			issuer = strings.TrimSpace(parts[0])
		}

		// Get primary client ID / audience
		aud := api.DefaultAudience
		if len(h.AllowedAudiences) > 0 {
			aud = h.AllowedAudiences[0]
		}

		resp := &api.HubInfoResponse{
			OidcIssuer: issuer,
			ClientId:   aud,
			Audience:   aud,
		}

		respData, err := proto.Marshal(resp)
		if err != nil {
			logger.Errorf("[Info] Failed to marshal info response: %v", err)
			http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respData)
	}
}
