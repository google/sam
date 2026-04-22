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
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	samnet "sam/pkg/net"
)

// buildNode constructs a SAM mesh node from the shared runConfig flags.
// --hub is mandatory: the hub provides OIDC-backed passport issuance and
// acts as the mandatory P2P rendezvous/bootstrap point for the mesh.
// It also returns the hub's libp2p peer ID so callers can register it as
// a trusted peer (exempt from passport auth) before joining the mesh.
func buildNode(cfg *runConfig) (samnet.Node, libp2ppeer.ID, error) {
	hubURL := strings.TrimSpace(resolveHubURL(cfg))
	if hubURL == "" {
		return nil, "", fmt.Errorf("--hub (or SAM_HUB env) is required: the hub is the rendezvous point and passport issuer for the mesh")
	}

	listen, err := parseMultiaddrs(cfg.listenAddrs)
	if err != nil {
		return nil, "", fmt.Errorf("parsing --listen: %w", err)
	}

	key, err := loadOrGenerateKey(cfg.identityPath)
	if err != nil {
		return nil, "", fmt.Errorf("loading identity key: %w", err)
	}

	// Resolve hub hostname for rendezvous namespace and relay hint.
	hubHost := hubHostFromURL(hubURL)

	// Fetch hub P2P bootstrap addresses from the hub's well-known endpoint.
	// This is the primary rendezvous mechanism: all agents bootstrap through
	// the hub, which acts as DHT server and relay.
	hubBootstrap, hubPeerID, err := fetchHubP2PInfo(hubURL)
	if err != nil {
		slog.Default().Warn("could not fetch hub P2P addresses; hub may not be running in P2P mode", "hub", hubURL, "err", err)
	}

	opts := []samnet.Option{
		samnet.WithListenAddrs(listen...),
		samnet.WithBootstrapPeers(hubBootstrap...),
		samnet.WithDHTMode(parseDHTMode(cfg.dhtMode)),
		samnet.WithFederation(defaultFederationID),
		samnet.WithUserAgent(cfg.userAgent),
		samnet.WithLogger(slog.Default()),
		samnet.WithPrivateKey(key),
		samnet.WithRendezvousNamespace(hubHost),
		samnet.WithRelayFallbackHost(hubHost),
	}
	if cfg.withRelay {
		opts = append(opts, samnet.WithRelayService())
	}

	node, err := samnet.New(opts...)
	if err != nil {
		return nil, "", err
	}
	return node, hubPeerID, nil
}

// fetchHubP2PAddrs contacts the hub's /.well-known/sam-hub-p2p endpoint and
// returns the hub's libp2p multiaddrs for use as bootstrap/rendezvous peers.
// fetchHubP2PInfo contacts the hub's /.well-known/sam-hub-p2p endpoint and
// returns the hub's libp2p multiaddrs and peer ID.
func fetchHubP2PInfo(hubURL string) ([]multiaddr.Multiaddr, libp2ppeer.ID, error) {
	endpoint := strings.TrimRight(hubURL, "/") + "/.well-known/sam-hub-p2p"
	resp, err := http.Get(endpoint) //nolint:gosec // hubURL is user-supplied and validated
	if err != nil {
		return nil, "", fmt.Errorf("fetching hub P2P info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("hub P2P info returned %d", resp.StatusCode)
	}
	var info struct {
		PeerID string   `json:"peer_id"`
		Addrs  []string `json:"addrs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, "", fmt.Errorf("decoding hub P2P info: %w", err)
	}
	var out []multiaddr.Multiaddr
	for _, s := range info.Addrs {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			continue // skip malformed entries
		}
		out = append(out, ma)
	}
	hubPeer, _ := libp2ppeer.Decode(info.PeerID) // empty string if hub has no P2P mode
	return out, hubPeer, nil
}

func hubHostFromURL(hubURL string) string {
	u, err := url.Parse(strings.TrimSpace(hubURL))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(u.Hostname())
}

// loadOrGenerateKey loads a PEM-encoded libp2p Ed25519 private key from path.
//
//   - If path is empty an ephemeral key is generated.
//   - If path names an existing file the key is read from it.
//   - If path names a non-existent file a fresh key is generated and written
//     there (0600) so subsequent invocations are deterministic.
func loadOrGenerateKey(path string) (crypto.PrivKey, error) {
	if path == "" {
		return samnet.GenerateKey()
	}

	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no PEM block found in %s", path)
		}
		return crypto.UnmarshalPrivateKey(block.Bytes)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading identity file: %w", err)
	}

	// File does not exist — generate and persist.
	key, err := samnet.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	raw, err := crypto.MarshalPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling key: %w", err)
	}
	block := &pem.Block{Type: "LIBP2P PRIVATE KEY", Bytes: raw}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("writing identity file: %w", err)
	}
	slog.Default().Info("identity key created", "path", path)
	return key, nil
}

// parseMultiaddrs converts a slice of multiaddr strings into typed values.
func parseMultiaddrs(values []string) ([]multiaddr.Multiaddr, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]multiaddr.Multiaddr, 0, len(values))
	for _, value := range values {
		ma, err := multiaddr.NewMultiaddr(strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
		out = append(out, ma)
	}
	return out, nil
}

// parseDHTMode maps a flag string to the samnet.DHTMode constant.
func parseDHTMode(mode string) samnet.DHTMode {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "server":
		return samnet.DHTModeServer
	case "auto":
		return samnet.DHTModeAuto
	default:
		return samnet.DHTModeClient
	}
}

// waitForShutdown blocks until either the context is cancelled, a OS signal is
// received, or the optional runFor timer fires.
func waitForShutdown(parent context.Context, runFor time.Duration) error {
	if runFor > 0 {
		t := time.NewTimer(runFor)
		defer func() { _ = t.Stop() }()
		select {
		case <-parent.Done():
			return parent.Err()
		case <-t.C:
			return nil
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case <-parent.Done():
		return parent.Err()
	case <-sigCh:
		return nil
	}
}
