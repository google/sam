package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"sam/pkg/identity"
)

func newUpCmd(cfg *runConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Start a SAM node and initialize identity issuer/verifier",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUp(cmd.Context(), cfg)
		},
	}
	cmd.Flags().StringVar(&cfg.issuerName, "issuer", "sam.local", "identity issuer name for voucher bootstrap")
	return cmd
}

func runUp(parent context.Context, cfg *runConfig) error {
	log := slog.Default()
	if cfg.hub != "" {
		log.Info("hub configured", "url", cfg.hub)
	}

	node, err := buildNode(cfg)
	if err != nil {
		return err
	}
	if err := node.Start(parent); err != nil {
		return fmt.Errorf("starting node: %w", err)
	}
	defer node.Stop(context.Background())

	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating issuer key: %w", err)
	}
	iss, err := identity.NewIssuer(cfg.issuerName, signingKey)
	if err != nil {
		return fmt.Errorf("initializing issuer: %w", err)
	}
	if _, err = identity.NewVerifier(identity.WithTrustedIssuer(iss.Issuer(), iss.PublicKey())); err != nil {
		return fmt.Errorf("initializing verifier: %w", err)
	}

	addrs := make([]string, 0, len(node.Addrs()))
	for _, a := range node.Addrs() {
		addrs = append(addrs, a.String())
	}

	status := map[string]any{
		"peer_id":  node.PeerID().String(),
		"addrs":    addrs,
		"issuer":   iss.Issuer(),
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
