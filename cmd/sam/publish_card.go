package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"sam/pkg/protocol"
)

func newPublishCardCmd(cfg *runConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "card",
		Short: "Sign and publish an A2A agent card to the DHT",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPublishCard(cmd.Context(), cfg)
		},
	}
	_ = cmd.MarkPersistentFlagRequired("capability")
	_ = cmd.MarkPersistentFlagRequired("resource-name")
	return cmd
}

func runPublishCard(parent context.Context, cfg *runConfig) error {
	if len(cfg.capabilities) == 0 {
		return fmt.Errorf("at least one --capability is required")
	}

	node, err := buildNode(cfg)
	if err != nil {
		return err
	}
	if err := node.Start(parent); err != nil {
		return fmt.Errorf("starting node: %w", err)
	}
	defer func() { _ = node.Stop(context.Background()) }()

	priv := node.Host().Peerstore().PrivKey(node.PeerID())
	if priv == nil {
		return fmt.Errorf("local node private key unavailable")
	}

	resource := protocol.MCPResource{
		Name:        strings.TrimSpace(cfg.resourceName),
		Kind:        strings.TrimSpace(cfg.resourceKind),
		Endpoint:    strings.TrimSpace(cfg.resourceEP),
		Description: strings.TrimSpace(cfg.resourceDesc),
	}
	card, err := protocol.NewAgentCard(node.PeerID(), cfg.capabilities, []protocol.MCPResource{resource}, priv)
	if err != nil {
		return fmt.Errorf("building agent card: %w", err)
	}
	if err := attachNodeVouch(card, node.PeerID().String(), priv); err != nil {
		return err
	}

	pub, err := protocol.NewPublisher(node)
	if err != nil {
		return fmt.Errorf("creating publisher: %w", err)
	}
	if err := publishLoop(parent, pub, card, cfg.republishEvery); err != nil {
		return fmt.Errorf("publishing agent card: %w", err)
	}

	if err := json.NewEncoder(os.Stdout).Encode(card); err != nil {
		return fmt.Errorf("encoding published card: %w", err)
	}

	slog.Default().Info("agent card published",
		"peer_id", node.PeerID(),
		"capabilities", cfg.capabilities,
	)
	return waitForShutdown(parent, cfg.runFor)
}
