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
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

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
		allHubAddrs := getMyHubAddrs(h)

		resp := &api.EnrollResponse{
			BiscuitToken: biscuitData,
			HubPublicKey: h.KeyRing.GetCurrentPublicKey(),
			HubAddresses: allHubAddrs,
			Expiration:   token.Expiry.Unix(),
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

func getMyHubAddrs(h *Hub) []string {
	var addrs []string
	if len(h.ExternalAddrs) > 0 {
		for _, addr := range h.ExternalAddrs {
			addrs = append(addrs, addr+"/p2p/"+h.Host.ID().String())
		}
	} else {
		for _, addr := range h.Host.Addrs() {
			if h.AllowLoopback {
				addrs = append(addrs, addr.String()+"/p2p/"+h.Host.ID().String())
			} else {
				// We don't have isLoopbackOrLinkLocal easily here so just include all or rely on AddrsFactory from main.go
				addrs = append(addrs, addr.String()+"/p2p/"+h.Host.ID().String())
			}
		}
	}
	return addrs
}
