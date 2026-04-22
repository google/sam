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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multihash"
	"github.com/spf13/cobra"

	"sam/pkg/identity"
	samnet "sam/pkg/net"
	"sam/pkg/protocol"
)

func newProxyCmd(cfg *runConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Start a local HTTP proxy tunnel over libp2p",
		Long: `Listen on a local HTTP port and forward requests through SAM.

The destination must be set on each request via X-SAM-Target:
  - PeerID: routes directly to a specific peer
  - Capability: discovers the closest provider via DHT and routes there`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProxy(cmd.Context(), cfg)
		},
	}

	f := cmd.Flags()
	f.IntVar(&cfg.proxyPort, "port", 0, "local HTTP listen port")
	f.StringVar(&cfg.proxyTargetHdr, "target-header", "X-SAM-Target", "request header used to select peer-id or capability")
	f.StringVar(&cfg.proxyBiscuit, "biscuit", "dev-biscuit", "biscuit token forwarded in tunnel metadata")
	f.DurationVar(&cfg.proxyTimeout, "timeout", 30*time.Second, "per-request tunnel timeout")
	_ = cmd.MarkFlagRequired("port")

	return cmd
}

func runProxy(parent context.Context, cfg *runConfig) error {
	if cfg.proxyPort <= 0 {
		return fmt.Errorf("--port must be a positive integer")
	}
	if strings.TrimSpace(cfg.proxyTargetHdr) == "" {
		cfg.proxyTargetHdr = "X-SAM-Target"
	}
	if cfg.proxyTimeout <= 0 {
		cfg.proxyTimeout = 30 * time.Second
	}

	node, err := buildNode(cfg)
	if err != nil {
		return err
	}
	if err := node.Start(parent); err != nil {
		return fmt.Errorf("starting node: %w", err)
	}
	defer func() { _ = node.Stop(context.Background()) }()

	discoverer, err := newAgentDiscoverer(node, defaultFederationID, 15*time.Minute)
	if err != nil {
		return fmt.Errorf("creating informer discoverer: %w", err)
	}
	informer, err := samnet.NewLocalInformer(node, defaultFederationID, samnet.WithInformerDiscoverer(discoverer))
	if err != nil {
		return fmt.Errorf("creating local informer: %w", err)
	}
	informer.Start(parent)

	watchManager, err := newInventoryWatchManager(node, defaultFederationID)
	if err != nil {
		return fmt.Errorf("creating inventory watch manager: %w", err)
	}
	defer func() {
		if closeErr := watchManager.Close(); closeErr != nil {
			slog.Warn("closing inventory watch manager", "err", closeErr)
		}
	}()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.sam/") {
			handleSAMReservedWithWatcher(w, r, node, cfg, watchManager)
			return
		}

		if _, authErr := extractBearerToken(r.Header.Get("Authorization")); authErr != nil {
			http.Error(w, fmt.Sprintf("unauthorized: %v", authErr), http.StatusUnauthorized)
			return
		}

		start := time.Now()
		observer, err := protocol.NewBoltObserverWithFallback(defaultFederationID)
		if err != nil {
			http.Error(w, "reputation observer unavailable", http.StatusInternalServerError)
			return
		}
		defer func() { _ = observer.Close() }()

		passport, vErr := loadLocalIdentityAuth()
		if vErr != nil {
			http.Error(w, "unauthorized: local identity login required", http.StatusUnauthorized)
			return
		}
		if err := identity.SetLocalPassport(node.Host(), defaultFederationID, passport); err != nil {
			http.Error(w, fmt.Sprintf("passport auth unavailable: %v", err), http.StatusInternalServerError)
			return
		}

		targetArg := strings.TrimSpace(r.Header.Get(cfg.proxyTargetHdr))
		if targetArg == "" {
			http.Error(w, fmt.Sprintf("missing %s header", cfg.proxyTargetHdr), http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), cfg.proxyTimeout)
		defer cancel()

		target, capability, err := resolveProxyTarget(ctx, node, targetArg)
		if err != nil {
			http.Error(w, fmt.Sprintf("target resolution failed: %v", err), http.StatusBadGateway)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			observer.OnFailure(target.ID.String(), protocol.FailureTypeProtocol)
			http.Error(w, fmt.Sprintf("reading request body: %v", err), http.StatusBadRequest)
			return
		}

		requestHeaders := r.Header.Clone()
		requestHeaders.Del(cfg.proxyTargetHdr)

		tunnelReq := protocol.HTTPTunnelRequest{
			Method:  r.Method,
			Path:    r.URL.RequestURI(),
			Headers: requestHeaders,
			Body:    body,
		}

		if cfg.debug {
			slog.Default().Info("proxy hop", "path", "[Local HTTP] -> ["+target.ID.String()+"] -> [Remote Service]")
		}

		if len(target.Addrs) > 0 {
			_ = node.Connect(ctx, target)
		}

		resp, err := protocol.TunnelHTTP(ctx, node.Host(), target.ID, protocol.HTTPTunnelOpenRequest{
			Biscuit:    strings.TrimSpace(cfg.proxyBiscuit),
			Capability: capability,
			Request:    tunnelReq,
		})
		if err != nil {
			observer.OnFailure(target.ID.String(), protocol.FailureTypeLiveness)
			http.Error(w, fmt.Sprintf("tunnel request failed: %v", err), http.StatusBadGateway)
			return
		}
		if resp.Error != "" {
			observer.OnFailure(target.ID.String(), protocol.FailureTypeRemote)
			status := resp.StatusCode
			if status == 0 {
				status = http.StatusBadGateway
			}
			http.Error(w, resp.Error, status)
			return
		}

		for key, vals := range resp.Headers {
			for _, val := range vals {
				w.Header().Add(key, val)
			}
		}
		status := resp.StatusCode
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(resp.Body)

		observer.OnSuccess(target.ID.String(), time.Since(start))
	})

	addr := ":" + strconv.Itoa(cfg.proxyPort)
	srv := &http.Server{Addr: addr, Handler: handler}
	go func() {
		<-parent.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	slog.Default().Info("SAM HTTP proxy is up", "peer_id", node.PeerID(), "listen", addr, "target_header", cfg.proxyTargetHdr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("starting local proxy HTTP server: %w", err)
	}
	return nil
}

func extractBearerToken(header string) (string, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", fmt.Errorf("missing Authorization header")
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "Bearer") {
		return "", fmt.Errorf("Authorization must use Bearer scheme")
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", fmt.Errorf("bearer token is empty")
	}
	return token, nil
}

func handleSAMReserved(w http.ResponseWriter, r *http.Request, node samnet.Node, cfg *runConfig) {
	handleSAMReservedWithWatcher(w, r, node, cfg, nil)
}

func handleSAMReservedWithWatcher(w http.ResponseWriter, r *http.Request, node samnet.Node, cfg *runConfig, watchManager *inventoryWatchManager) {
	ctx, cancel := context.WithTimeout(r.Context(), cfg.proxyTimeout)
	defer cancel()

	switch r.URL.Path {
	case "/.sam/watch/inventory":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if watchManager == nil {
			http.Error(w, "watch manager unavailable", http.StatusServiceUnavailable)
			return
		}
		watchManager.ServeInventoryWatch(w, r)
		return
	case "/.sam/inventory":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cards, err := aggregateInventory(ctx, node, defaultFederationID)
		if err != nil {
			http.Error(w, fmt.Sprintf("inventory lookup failed: %v", err), http.StatusBadGateway)
			return
		}
		writeJSON(w, cards)
	case "/.sam/mcp/inventory":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cards, err := aggregateInventory(ctx, node, defaultFederationID)
		if err != nil {
			http.Error(w, fmt.Sprintf("inventory lookup failed: %v", err), http.StatusBadGateway)
			return
		}
		writeJSON(w, buildGlobalMCPCatalog(cards))
	case "/.sam/search":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		skill := strings.TrimSpace(r.URL.Query().Get("skill"))
		if skill == "" {
			http.Error(w, "missing skill query parameter", http.StatusBadRequest)
			return
		}
		cards, err := searchInventoryBySkill(ctx, node, defaultFederationID, skill)
		if err != nil {
			http.Error(w, fmt.Sprintf("search failed: %v", err), http.StatusBadGateway)
			return
		}
		writeJSON(w, cards)
	default:
		http.NotFound(w, r)
	}
}

func aggregateInventory(ctx context.Context, node samnet.Node, federation string) ([]*protocol.AgentCard, error) {
	cached, err := decodeCachedAgentCards(federation)
	if err != nil {
		return nil, err
	}

	byPeer := make(map[string]*protocol.AgentCard, len(cached))
	capabilities := map[string]struct{}{}
	for _, card := range cached {
		if card == nil || strings.TrimSpace(card.PeerID) == "" {
			continue
		}
		byPeer[card.PeerID] = card
		for _, capName := range card.CapabilityNames() {
			capabilities[capName] = struct{}{}
		}
	}

	for capability := range capabilities {
		liveCards, err := discoverCardsByCapability(ctx, node, capability)
		if err != nil {
			continue
		}
		for _, card := range liveCards {
			if card == nil || strings.TrimSpace(card.PeerID) == "" {
				continue
			}
			byPeer[card.PeerID] = card
			_ = upsertAgentCardRecord(federation, card)
		}
	}

	out := make([]*protocol.AgentCard, 0, len(byPeer))
	for _, card := range byPeer {
		out = append(out, card)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PeerID < out[j].PeerID })
	return out, nil
}

func searchInventoryBySkill(ctx context.Context, node samnet.Node, federation, skill string) ([]*protocol.AgentCard, error) {
	byPeer := map[string]*protocol.AgentCard{}

	cached, _ := decodeCachedAgentCards(federation)
	for _, card := range cached {
		if cardHasCapability(card, skill) {
			byPeer[card.PeerID] = card
		}
	}

	liveCards, err := discoverCardsByCapability(ctx, node, skill)
	if err != nil {
		if len(byPeer) == 0 {
			return nil, err
		}
	} else {
		for _, card := range liveCards {
			if card == nil || strings.TrimSpace(card.PeerID) == "" {
				continue
			}
			byPeer[card.PeerID] = card
			_ = upsertAgentCardRecord(federation, card)
		}
	}

	out := make([]*protocol.AgentCard, 0, len(byPeer))
	for _, card := range byPeer {
		out = append(out, card)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PeerID < out[j].PeerID })
	return out, nil
}

func discoverCardsByCapability(ctx context.Context, node samnet.Node, capability string) ([]*protocol.AgentCard, error) {
	ns := protocol.AgentCapabilityNamespace(capability)
	peerInfos, err := findProvidersForNamespace(ctx, node, ns)
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	cards := make([]*protocol.AgentCard, 0, len(peerInfos))
	for _, pi := range peerInfos {
		if pi.ID == "" {
			continue
		}
		pid := pi.ID.String()
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}

		if len(pi.Addrs) > 0 {
			_ = node.Connect(ctx, pi)
		}
		card, err := fetchCardFromDHT(ctx, node, pid)
		if err != nil {
			continue
		}
		if !cardHasCapability(card, capability) {
			continue
		}
		cards = append(cards, card)
	}
	return cards, nil
}

func findProvidersForNamespace(ctx context.Context, node samnet.Node, namespace string) ([]peer.AddrInfo, error) {
	d := node.DHT()
	if d == nil {
		return nil, fmt.Errorf("dht is not available")
	}
	topicCID, err := namespaceToCID(namespace)
	if err != nil {
		return nil, err
	}

	results := make([]peer.AddrInfo, 0)
	seen := map[string]struct{}{}
	for info := range d.FindProvidersAsync(ctx, topicCID, 64) {
		if info.ID == "" || info.ID == node.PeerID() {
			continue
		}
		if _, ok := seen[info.ID.String()]; ok {
			continue
		}
		seen[info.ID.String()] = struct{}{}
		results = append(results, info)
	}
	return results, nil
}

func namespaceToCID(namespace string) (cid.Cid, error) {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return cid.Undef, fmt.Errorf("namespace is required")
	}
	h, err := multihash.Sum([]byte(namespace), multihash.SHA2_256, -1)
	if err != nil {
		return cid.Undef, fmt.Errorf("hashing namespace: %w", err)
	}
	return cid.NewCidV1(cid.Raw, h), nil
}

func fetchCardFromDHT(ctx context.Context, node samnet.Node, peerID string) (*protocol.AgentCard, error) {
	raw, err := node.GetValue(ctx, protocol.DHTPeerCardKey(peerID))
	if err != nil {
		return nil, err
	}
	var card protocol.AgentCard
	if err := json.Unmarshal(raw, &card); err != nil {
		return nil, fmt.Errorf("decoding agent card: %w", err)
	}
	if err := protocol.VerifyAgentCard(&card); err != nil {
		return nil, fmt.Errorf("validating agent card: %w", err)
	}
	return &card, nil
}

func cardHasCapability(card *protocol.AgentCard, capability string) bool {
	if card == nil {
		return false
	}
	want := strings.ToLower(strings.TrimSpace(capability))
	if want == "" {
		return false
	}
	for _, c := range card.CapabilityNames() {
		if strings.EqualFold(c, want) {
			return true
		}
	}
	return false
}

type meshToolEntry struct {
	URI         string `json:"uri"`
	PeerID      string `json:"peer_id"`
	Name        string `json:"name"`
	Kind        string `json:"kind,omitempty"`
	Capability  string `json:"capability,omitempty"`
	Description string `json:"description,omitempty"`
}

func buildGlobalMCPCatalog(cards []*protocol.AgentCard) []meshToolEntry {
	out := make([]meshToolEntry, 0)
	for _, card := range cards {
		if card == nil || strings.TrimSpace(card.PeerID) == "" {
			continue
		}
		for _, res := range card.Resources {
			name := strings.TrimSpace(res.Name)
			if name == "" {
				continue
			}
			out = append(out, meshToolEntry{
				URI:         fmt.Sprintf("mesh://%s/%s", card.PeerID, name),
				PeerID:      card.PeerID,
				Name:        name,
				Kind:        strings.TrimSpace(res.Kind),
				Description: strings.TrimSpace(res.Description),
			})
		}
		if len(card.Resources) > 0 {
			continue
		}
		for _, capability := range card.CapabilityNames() {
			out = append(out, meshToolEntry{
				URI:        fmt.Sprintf("mesh://%s/%s", card.PeerID, capability),
				PeerID:     card.PeerID,
				Name:       capability,
				Capability: capability,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PeerID == out[j].PeerID {
			return out[i].Name < out[j].Name
		}
		return out[i].PeerID < out[j].PeerID
	})
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, fmt.Sprintf("encoding response: %v", err), http.StatusInternalServerError)
	}
}

func resolveProxyTarget(ctx context.Context, node samnet.Node, targetArg string) (peer.AddrInfo, string, error) {
	targetArg = strings.TrimSpace(targetArg)
	if targetArg == "" {
		return peer.AddrInfo{}, "", fmt.Errorf("target peer ID or capability is required")
	}

	if pid, err := peer.Decode(targetArg); err == nil {
		return peer.AddrInfo{ID: pid, Addrs: node.Host().Peerstore().Addrs(pid)}, "", nil
	}

	svc, err := protocol.NewDiscoveryService(node)
	if err != nil {
		return peer.AddrInfo{}, "", fmt.Errorf("creating discovery service: %w", err)
	}
	peers, err := svc.DiscoverPeers(ctx, targetArg)
	if err != nil {
		return peer.AddrInfo{}, "", fmt.Errorf("discovering capability %q: %w", targetArg, err)
	}
	if len(peers) == 0 {
		return peer.AddrInfo{}, "", fmt.Errorf("no peers found for capability %q", targetArg)
	}

	closest := closestPeer(node.PeerID(), peers)
	return closest, targetArg, nil
}

func closestPeer(local peer.ID, peers []peer.AddrInfo) peer.AddrInfo {
	if len(peers) == 1 {
		return peers[0]
	}
	localBytes := []byte(local)
	best := peers[0]
	bestDistance := xorDistance(localBytes, []byte(best.ID))
	for i := 1; i < len(peers); i++ {
		d := xorDistance(localBytes, []byte(peers[i].ID))
		if d.Cmp(bestDistance) < 0 {
			best = peers[i]
			bestDistance = d
		}
	}
	return best
}

func xorDistance(a, b []byte) *big.Int {
	max := len(a)
	if len(b) > max {
		max = len(b)
	}
	buf := make([]byte, max)
	for i := 0; i < max; i++ {
		var av, bv byte
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		buf[i] = av ^ bv
	}
	return new(big.Int).SetBytes(buf)
}
