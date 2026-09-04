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

package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// Bound the diagnostic dials so a dead peer yields an error instead of a
// request that hangs for as long as the caller's patience.
const (
	connectivityPingTimeout = 15 * time.Second
	connectPeerTimeout      = 30 * time.Second
)

// newDebugHandler serves the operator diagnostics under /debug. These were MCP
// tools once; they moved here so agents never see them in their tool list (#318).
func newDebugHandler(n *SamNode) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/mesh-info", func(w http.ResponseWriter, r *http.Request) {
		info, err := n.meshInfo()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeDebugJSON(w, info)
	})
	mux.HandleFunc("GET /debug/connectivity", func(w http.ResponseWriter, r *http.Request) {
		writeDebugJSON(w, n.connectivityStats(r.Context(), r.URL.Query().Get("peer_id")))
	})
	mux.HandleFunc("GET /debug/network-info", func(w http.ResponseWriter, r *http.Request) {
		writeDebugJSON(w, n.networkInfo())
	})
	mux.HandleFunc("GET /debug/token-info", func(w http.ResponseWriter, r *http.Request) {
		writeDebugJSON(w, n.tokenInfo())
	})
	mux.HandleFunc("GET /debug/logs", func(w http.ResponseWriter, r *http.Request) {
		writeDebugJSON(w, logsResponse{Logs: GetRecentLogs()})
	})
	mux.HandleFunc("POST /debug/connect-peer", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PeerAddr string `json:"peer_addr"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if req.PeerAddr == "" {
			http.Error(w, "peer_addr is required", http.StatusBadRequest)
			return
		}
		if err := n.connectPeer(r.Context(), req.PeerAddr); err != nil {
			http.Error(w, fmt.Sprintf("Failed to connect: %v", err), http.StatusInternalServerError)
			return
		}
		writeDebugJSON(w, map[string]string{"status": "connected"})
	})

	// One guard for every handler: refuse loudly on a half-built node instead
	// of panicking mid-request or fabricating zero-value diagnostics.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := n.debugReady(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// debugReady reports whether the components the /debug handlers touch exist.
func (n *SamNode) debugReady() error {
	switch {
	case n == nil:
		return fmt.Errorf("node not initialized")
	case n.Host == nil:
		return fmt.Errorf("libp2p host not initialized")
	case n.DHT == nil:
		return fmt.Errorf("DHT not initialized")
	case n.Store == nil:
		return fmt.Errorf("node store not initialized")
	}
	return nil
}

func writeDebugJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Errorf("Failed to encode response: %v", err)
	}
}

// The types below are the /debug payloads. They are unexported on purpose:
// these endpoints are unversioned operator diagnostics, not part of the
// api/sam.proto mesh contract.

type meshInfoResponse struct {
	PeerID         string   `json:"peer_id"`
	ConnectedPeers []string `json:"connected_peers"`
	DHTSize        int      `json:"dht_size"`
	RouterPeerID   string   `json:"router_peer_id"`
	LocalAPISocket string   `json:"local_api_socket,omitempty"`
}

type connectivityResponse struct {
	ConnectedPeers  int    `json:"connected_peers"`
	TotalKnownPeers int    `json:"total_known_peers"`
	PingLatencyMS   *int64 `json:"ping_latency_ms,omitempty"`
	PingError       *bool  `json:"ping_error,omitempty"`
	PingErrorMsg    string `json:"ping_error_msg,omitempty"`
	RouterLatencyMS *int64 `json:"router_latency_ms,omitempty"`
	RouterError     *bool  `json:"router_error,omitempty"`
	RouterErrorMsg  string `json:"router_error_msg,omitempty"`
}

type tokenInfoResponse struct {
	HasToken         bool     `json:"has_token"`
	ExpiresInSeconds *float64 `json:"expires_in_seconds,omitempty"`
	IsExpired        *bool    `json:"is_expired,omitempty"`
}

type networkInfoResponse struct {
	ListenAddresses   []string `json:"listen_addresses"`
	ObservedAddresses []string `json:"observed_addresses"`
}

type logsResponse struct {
	Logs []string `json:"logs"`
}

// meshInfo backs both the get_mesh_info MCP tool and GET /debug/mesh-info.
// The MCP path skips the /debug boundary guard, so it re-checks here.
func (n *SamNode) meshInfo() (*meshInfoResponse, error) {
	if err := n.debugReady(); err != nil {
		return nil, err
	}

	peers := n.Host.Network().Peers()
	// Pre-sized so zero peers serializes as [] rather than null.
	connectedPeers := make([]string, 0, len(peers))
	for _, p := range peers {
		connectedPeers = append(connectedPeers, p.String())
	}

	return &meshInfoResponse{
		PeerID:         n.Host.ID().String(),
		ConnectedPeers: connectedPeers,
		DHTSize:        n.DHT.RoutingTable().Size(),
		RouterPeerID:   n.RouterPeerID.String(),
		LocalAPISocket: n.BoundSocketPath,
	}, nil
}

// connectivityStats backs GET /debug/connectivity: with a peer ID it pings that
// peer, otherwise it pings the SAM router.
func (n *SamNode) connectivityStats(ctx context.Context, peerIDStr string) connectivityResponse {
	ctx, cancel := context.WithTimeout(ctx, connectivityPingTimeout)
	defer cancel()

	stats := connectivityResponse{
		ConnectedPeers:  len(n.Host.Network().Peers()),
		TotalKnownPeers: len(n.Host.Peerstore().Peers()),
	}

	if peerIDStr != "" {
		pid, err := peer.Decode(peerIDStr)
		if err == nil {
			n.preparePeerAddrs(ctx, pid)
			start := time.Now()
			err := n.Host.Connect(ctx, peer.AddrInfo{ID: pid})
			latency := time.Since(start).Milliseconds()
			failed := err != nil
			stats.PingLatencyMS = &latency
			stats.PingError = &failed
			if err != nil {
				stats.PingErrorMsg = err.Error()
			}
		} else {
			failed := true
			stats.PingError = &failed
			stats.PingErrorMsg = "invalid peer id"
		}
	} else if n.RouterPeerID != "" {
		start := time.Now()
		err := n.Host.Connect(ctx, peer.AddrInfo{ID: n.RouterPeerID})
		latency := time.Since(start).Milliseconds()
		failed := err != nil
		stats.RouterLatencyMS = &latency
		stats.RouterError = &failed
		if err != nil {
			stats.RouterErrorMsg = err.Error()
		}
	}

	return stats
}

// tokenInfo backs GET /debug/token-info.
func (n *SamNode) tokenInfo() tokenInfoResponse {
	var info tokenInfoResponse
	token, err := n.Store.LoadIdentity()
	if err == nil && len(token) > 0 {
		info.HasToken = true
		exp, err := n.Store.LoadIdentityExpiration()
		if err == nil {
			expiresIn := time.Until(time.Unix(exp, 0)).Seconds()
			expired := time.Now().Unix() > exp
			info.ExpiresInSeconds = &expiresIn
			info.IsExpired = &expired
		}
	}
	return info
}

// networkInfo backs GET /debug/network-info.
func (n *SamNode) networkInfo() networkInfoResponse {
	listenAddrs := []string{}
	for _, a := range n.Host.Network().ListenAddresses() {
		listenAddrs = append(listenAddrs, a.String())
	}

	observedAddrs := []string{}
	for _, a := range n.Host.Addrs() {
		observedAddrs = append(observedAddrs, a.String())
	}

	return networkInfoResponse{
		ListenAddresses:   listenAddrs,
		ObservedAddresses: observedAddrs,
	}
}

// connectPeer backs POST /debug/connect-peer.
func (n *SamNode) connectPeer(ctx context.Context, peerAddr string) error {
	ctx, cancel := context.WithTimeout(ctx, connectPeerTimeout)
	defer cancel()

	ma, err := multiaddr.NewMultiaddr(peerAddr)
	if err != nil {
		return err
	}
	addrInfo, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return err
	}
	if n.revokedPeers != nil && n.revokedPeers.Contains(addrInfo.ID.String()) {
		return fmt.Errorf("failed to dial: failed to dial %s: gater disallows connection to peer", addrInfo.ID)
	}
	conns := n.Host.Network().ConnsToPeer(addrInfo.ID)
	connectedness := n.Host.Network().Connectedness(addrInfo.ID)
	logger.Debugf("[connect-peer] Target peer %s, connectedness: %v, active conns: %d", addrInfo.ID, connectedness, len(conns))

	err = n.Host.Connect(ctx, *addrInfo)
	logger.Debugf("[connect-peer] Host.Connect returned error: %v", err)
	return err
}
