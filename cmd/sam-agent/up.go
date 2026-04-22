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
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"sam/pkg/economy"
	"sam/pkg/identity"
	"sam/pkg/protocol"
)

func newUpCmd(cfg *runConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Start a SAM node",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUp(cmd.Context(), cfg)
		},
	}
	cmd.Flags().StringVar(&cfg.tunnelHTTPEndpoint, "tunnel-http-endpoint", "", "optional local HTTP endpoint exposed via /sam/tunnel/http/1.0 (for example http://127.0.0.1:11434)")
	return cmd
}

func runUp(parent context.Context, cfg *runConfig) error {
	log := slog.Default()

	// Require a hub-issued passport biscuit before joining the mesh.
	// Agents must authenticate via the hub's OIDC flow first:
	//   sam-agent identity login --hub <hub-url>
	creds, err := loadRequiredPassport(cfg)
	if err != nil {
		return err
	}

	node, hubPeerID, err := buildNode(cfg)
	if err != nil {
		return err
	}

	// Register the hub as a trusted peer before starting the node.
	// The hub is infrastructure — it doesn't run passport auth — so we
	// must exempt it from the connection-close-on-auth-failure gate.
	if hubPeerID != "" {
		identity.RegisterTrustedPeer(node.Host(), hubPeerID)
	}

	if err := node.Start(parent); err != nil {
		return fmt.Errorf("starting node: %w", err)
	}
	defer func() { _ = node.Stop(context.Background()) }()

	// Set the local passport so this node can prove its hub-issued identity
	// to every peer it connects to. No biscuit = no mesh participation.
	if err := identity.SetLocalPassport(node.Host(), defaultFederationID, creds.PassportBiscuit); err != nil {
		return fmt.Errorf("installing passport: %w", err)
	}
	log.Info("hub configured", "url", cfg.hub, "peer_id", creds.PeerID)

	var tunnel *protocol.HTTPTunnelService
	if cfg.tunnelHTTPEndpoint != "" {
		tunnel, err = protocol.NewHTTPTunnelService(
			node.Host(),
			cfg.tunnelHTTPEndpoint,
			protocol.WithHTTPTunnelSkillGate(economy.NewBiscuitSkillGate(nil)),
		)
		if err != nil {
			return fmt.Errorf("initializing HTTP tunnel listener: %w", err)
		}
		defer tunnel.Close()
		log.Info("HTTP tunnel listener enabled", "protocol", protocol.HTTPTunnelProtocolID, "endpoint", cfg.tunnelHTTPEndpoint)
	}

	addrs := make([]string, 0, len(node.Addrs()))
	for _, a := range node.Addrs() {
		addrs = append(addrs, a.String())
	}

	status := map[string]any{
		"peer_id":  node.PeerID().String(),
		"addrs":    addrs,
		"dht_mode": cfg.dhtMode,
	}
	if err := json.NewEncoder(os.Stdout).Encode(status); err != nil {
		return fmt.Errorf("encoding status: %w", err)
	}

	log.Info("SAM node is up",
		"peer_id", node.PeerID(),
		"addrs", addrs,
		"dht_mode", cfg.dhtMode,
	)

	return waitForShutdown(parent, cfg.runFor)
}

// loadRequiredPassport loads stored credentials and returns an error with
// actionable guidance if no hub-issued passport biscuit is found.
// Every agent must authenticate via the hub OIDC flow before joining the mesh.
func loadRequiredPassport(cfg *runConfig) (*identity.StoredCredentials, error) {
	store, err := identity.DefaultCredentialStore()
	if err != nil {
		return nil, fmt.Errorf("opening credential store: %w", err)
	}
	defer func() { _ = store.Close() }()

	creds, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("loading credentials: %w", err)
	}
	hub := resolveHubURL(cfg)
	if creds == nil || creds.PassportBiscuit == "" {
		return nil, fmt.Errorf(
			"no hub-issued passport found — authenticate first: sam-agent identity login --hub %s", hub)
	}
	return creds, nil
}
