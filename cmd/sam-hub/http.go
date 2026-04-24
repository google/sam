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
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
)

// authMiddleware protects HTTP endpoints by requiring a valid Hub-issued Biscuit
func (h *Hub) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized: missing Authorization header", http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		data, err := base64.StdEncoding.DecodeString(tokenStr)
		if err != nil {
			http.Error(w, "Unauthorized: invalid base64 encoding", http.StatusUnauthorized)
			return
		}

		b, err := biscuit.Unmarshal(data)
		if err != nil {
			http.Error(w, "Unauthorized: invalid biscuit token", http.StatusUnauthorized)
			return
		}

		// The Hub verifies the token using its own derived public key
		pubKey := h.BiscuitKey.Public().(ed25519.PublicKey)
		authorizer, err := b.Authorizer(pubKey)
		if err != nil {
			http.Error(w, "Unauthorized: signature verification failed", http.StatusUnauthorized)
			return
		}

		if err := authorizer.Authorize(); err != nil {
			http.Error(w, "Forbidden: invalid capabilities or wrong mesh", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func (h *Hub) handleLogin(w http.ResponseWriter, r *http.Request) {
	pID := r.URL.Query().Get("peer_id")
	if pID == "" {
		http.Error(w, "Missing peer_id", 400)
		return
	}
	// Bind PeerID as the OIDC 'state'
	url := h.OIDCConfig.AuthCodeURL(pID)
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *Hub) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	peerIDStr := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	token, err := h.OIDCConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Token exchange failed", 500)
		return
	}

	var claims struct {
		Subject string   `json:"sub"`
		Email   string   `json:"email"`
		Groups  []string `json:"groups"`
	}

	if h.AuthProvider == "oauth2" {
		req, _ := http.NewRequest("GET", h.OAuth2UserURL, nil)
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			http.Error(w, "Failed to fetch user info from OAuth2 provider", 500)
			return
		}
		defer resp.Body.Close()

		var userData map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
			http.Error(w, "Failed to parse user info JSON", 500)
			return
		}

		if sub, ok := userData[h.OAuth2UserField]; ok {
			claims.Subject = fmt.Sprintf("%v", sub)
		} else {
			http.Error(w, "User ID field not found in response", 500)
			return
		}

		if email, ok := userData[h.OAuth2EmailField]; ok {
			claims.Email = fmt.Sprintf("%v", email)
		}
	} else {
		rawID, _ := token.Extra("id_token").(string)
		idToken, err := h.Verifier.Verify(ctx, rawID)
		if err != nil {
			http.Error(w, "ID Token verification failed", http.StatusUnauthorized)
			return
		}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "Failed to parse claims", 500)
			return
		}
	}

	p, err := peer.Decode(peerIDStr)
	if err != nil {
		http.Error(w, "Invalid peer_id", 400)
		return
	}

	// Issue the Biscuit using Standard Vocabulary
	biscuitToken, err := h.issueStandardBiscuit(p, claims.Subject, claims.Email, claims.Groups)
	if err != nil {
		http.Error(w, "Biscuit issuance failed", 500)
		return
	}

	// Unlock the Mesh Firewall for this PeerID
	h.gater.mu.Lock()
	h.gater.authenticated[p] = true
	delete(h.gater.pending, p)
	h.gater.mu.Unlock()

	w.Header().Set("Content-Type", "text/html")
	if _, err := fmt.Fprintf(w, `<html><body>
		<h3>Sovereign Identity Verified!</h3>
		<p>Peer <code>%s</code> is now part of mesh <code>%s</code></p>
		<p>Identity: <code>%s</code></p>
		<hr/>
		<p>Standard Identity Biscuit:</p>
		<textarea rows="5" cols="60">%s</textarea>
	</body></html>`, p, h.MeshID, claims.Email, biscuitToken); err != nil {
		log.Printf("writing callback response: %v", err)
	}
}

// handleConfig provides the public key and bootstrap addresses over standard HTTP
func (h *Hub) handleConfig(w http.ResponseWriter, r *http.Request) {
	// Extract the Hub's public multiaddresses
	addrs, _ := peer.AddrInfoToP2pAddrs(host.InfoFromHost(h.Host))
	var addrStrs []string
	for _, a := range addrs {
		addrStrs = append(addrStrs, a.String())
	}

	pubKey := h.BiscuitKey.Public().(ed25519.PublicKey)

	config := &api.HubConfig{
		PublicKeyHex:   hex.EncodeToString(pubKey),
		MeshId:         h.MeshID,
		BootstrapNodes: addrStrs,
	}
	b, err := protojson.Marshal(config)
	if err != nil {
		http.Error(w, "Failed to marshal config", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(b); err != nil {
		log.Printf("writing config response: %v", err)
	}
}

// handlePeers returns the registry of enrolled peers
func (h *Hub) handlePeers(w http.ResponseWriter, r *http.Request) {
	h.gater.mu.RLock()
	defer h.gater.mu.RUnlock()

	peers := make([]string, 0, len(h.gater.authenticated))
	for pID := range h.gater.authenticated {
		peers = append(peers, pID.String())
	}

	registry := &api.PeerRegistry{
		Peers: make(map[string]*api.PeerProfile),
	}
	for _, pID := range peers {
		registry.Peers[pID] = &api.PeerProfile{}
	}
	b, err := protojson.Marshal(registry)
	if err != nil {
		http.Error(w, "Failed to marshal peers", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(b); err != nil {
		log.Printf("writing peers response: %v", err)
	}
}
