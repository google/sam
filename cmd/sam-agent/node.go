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
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"

	samnet "sam/pkg/net"
)

// buildNode constructs a SAM mesh node from the shared runConfig flags.
func buildNode(cfg *runConfig) (samnet.Node, error) {
	listen, err := parseMultiaddrs(cfg.listenAddrs)
	if err != nil {
		return nil, fmt.Errorf("parsing --listen: %w", err)
	}
	bootstrap, err := parseMultiaddrs(cfg.bootstrapAddrs)
	if err != nil {
		return nil, fmt.Errorf("parsing --bootstrap: %w", err)
	}

	key, err := loadOrGenerateKey(cfg.identityPath)
	if err != nil {
		return nil, fmt.Errorf("loading identity key: %w", err)
	}

	opts := []samnet.Option{
		samnet.WithListenAddrs(listen...),
		samnet.WithBootstrapPeers(bootstrap...),
		samnet.WithDHTMode(parseDHTMode(cfg.dhtMode)),
		samnet.WithFederation(defaultFederationID),
		samnet.WithUserAgent(cfg.userAgent),
		samnet.WithLogger(slog.Default()),
		samnet.WithPrivateKey(key),
	}
	if cfg.withRelay {
		opts = append(opts, samnet.WithRelayService())
	}

	return samnet.New(opts...)
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
