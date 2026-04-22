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
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/spf13/cobra"

	"sam/pkg/economy"
	samnet "sam/pkg/net"
	"sam/pkg/protocol"
)

// newPublishCmd creates the "sam publish" group command and attaches its
// subcommands.  It owns the flags that are shared between publish card and
// publish mcp.
func newPublishCmd(cfg *runConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Publish an agent card to DHT namespaces",
		Long: `Publish a signed SAM AgentCard into the DHT and keep re-providing it.

Quick usage:
  sam publish --skill weather-bot --mcp-port 8080

Advanced usage remains available via subcommands:
  sam publish card ...
  sam publish mcp ...`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPublish(cmd.Context(), cfg)
		},
	}

	// Shared flags inherited by both publish subcommands.
	f := cmd.PersistentFlags()
	f.StringSliceVar(&cfg.capabilities, "capability", nil, "capability to publish (repeatable)")
	f.StringVar(&cfg.skill, "skill", "", "single skill to publish (alias for one --capability)")
	f.StringVar(&cfg.resourceName, "resource-name", "", "MCP resource name")
	f.StringVar(&cfg.resourceKind, "resource-kind", "tool", "MCP resource kind")
	f.StringVar(&cfg.resourceEP, "resource-endpoint", "", "MCP resource endpoint")
	f.StringVar(&cfg.resourceDesc, "resource-description", "", "MCP resource description")
	f.DurationVar(&cfg.republishEvery, "republish-every", 2*time.Minute, "interval to refresh DHT announcements")
	f.StringVar(&cfg.dryRun, "dry-run", "", "dry-run mode: 'client' (no network) or 'server' (skip DHT commit)")

	cmd.Flags().IntVar(&cfg.mcpPort, "mcp-port", 0, "local MCP port for quick publish mode")

	cmd.AddCommand(newPublishCardCmd(cfg))
	cmd.AddCommand(newPublishMCPCmd(cfg))
	return cmd
}

func runPublish(parent context.Context, cfg *runConfig) error {
	if cfg.skill == "" && len(cfg.capabilities) == 0 {
		return fmt.Errorf("quick mode requires --skill (or use a publish subcommand)")
	}
	if cfg.mcpPort <= 0 {
		return fmt.Errorf("quick mode requires --mcp-port (or use sam publish mcp --port)")
	}

	capabilities := append([]string{}, cfg.capabilities...)
	if cfg.skill != "" {
		capabilities = append(capabilities, cfg.skill)
	}
	cfg.capabilities = normalizeValues(capabilities)
	if len(cfg.capabilities) == 0 {
		return fmt.Errorf("at least one non-empty skill/capability is required")
	}
	if err := ensureSecurePublishPreflight(); err != nil {
		return err
	}

	// For dry-run=client mode, skip network and just build the card
	if cfg.dryRun == "client" {
		return runPublishDryRunClient(cfg)
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

	resourceName := strings.TrimSpace(cfg.resourceName)
	if resourceName == "" {
		resourceName = cfg.capabilities[0]
	}
	resource := protocol.MCPResource{
		Name:        resourceName,
		Kind:        strings.TrimSpace(cfg.resourceKind),
		Endpoint:    fmt.Sprintf("http://127.0.0.1:%d", cfg.mcpPort),
		Description: strings.TrimSpace(cfg.resourceDesc),
	}

	card, err := protocol.NewAgentCard(node.PeerID(), cfg.capabilities, []protocol.MCPResource{resource}, priv)
	if err != nil {
		return fmt.Errorf("building agent card: %w", err)
	}
	if err := registerLocalAgentCard(node, card); err != nil {
		return err
	}

	// For dry-run=server mode, skip DHT but still build network
	if cfg.dryRun == "server" {
		return outputCard(card, cfg.outputFormat)
	}

	connector := &httpMCPConnector{
		client: &http.Client{Timeout: 30 * time.Second},
		addr:   fmt.Sprintf("http://127.0.0.1:%d", cfg.mcpPort),
	}
	if _, err := protocol.NewMCPBridge(node.Host(), economy.AllowAllVerifier{}, connector); err != nil {
		return fmt.Errorf("creating MCP bridge: %w", err)
	}

	pub, err := protocol.NewPublisher(node)
	if err != nil {
		return fmt.Errorf("creating publisher: %w", err)
	}
	if err := publishLoop(parent, pub, card, cfg.republishEvery); err != nil {
		return err
	}

	if err := json.NewEncoder(os.Stdout).Encode(card); err != nil {
		return fmt.Errorf("encoding published card: %w", err)
	}
	return waitForShutdown(parent, cfg.runFor)
}

func ensureSecurePublishPreflight() error {
	gate, closeFn, err := protocol.NewPassportGateWithCleanup()
	if err != nil {
		return fmt.Errorf("publish security preflight failed: %w", err)
	}
	defer func() { _ = closeFn() }()
	if protocol.IsAllowAllGate(gate) {
		return fmt.Errorf("refusing publish: A2A authentication middleware is permissive (AllowAllGate)")
	}
	return nil
}

func registerLocalAgentCard(node samnet.Node, card *protocol.AgentCard) error {
	svc, err := protocol.NewDiscoveryService(node)
	if err != nil {
		return fmt.Errorf("creating local discovery service: %w", err)
	}
	if err := svc.RegisterLocalCard(card); err != nil {
		return fmt.Errorf("registering local agent card stream: %w", err)
	}
	return nil
}

func publishLoop(parent context.Context, pub *protocol.Publisher, card *protocol.AgentCard, every time.Duration) error {
	if every <= 0 {
		every = 2 * time.Minute
	}
	retryTicker := time.NewTicker(250 * time.Millisecond)
	defer retryTicker.Stop()
	for {
		if err := pub.Publish(parent, card); err == nil {
			break
		} else {
			select {
			case <-parent.Done():
				return fmt.Errorf("initial publish failed: %w", err)
			case <-retryTicker.C:
			}
		}
	}
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-parent.Done():
				return
			case <-ticker.C:
				_ = pub.Publish(parent, card)
			}
		}
	}()
	return nil
}

func normalizeValues(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		v := strings.TrimSpace(item)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// runPublishDryRunClient builds a card without any network activity
func runPublishDryRunClient(cfg *runConfig) error {
	// Generate a temporary identity for card signing
	privKey, err := samnet.GenerateKey()
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	// Create a peer ID from the key
	peerID, err := peer.IDFromPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("creating peer ID: %w", err)
	}

	resourceName := strings.TrimSpace(cfg.resourceName)
	if resourceName == "" {
		resourceName = cfg.capabilities[0]
	}
	resource := protocol.MCPResource{
		Name:        resourceName,
		Kind:        strings.TrimSpace(cfg.resourceKind),
		Endpoint:    fmt.Sprintf("http://127.0.0.1:%d", cfg.mcpPort),
		Description: strings.TrimSpace(cfg.resourceDesc),
	}

	card, err := protocol.NewAgentCard(peerID, cfg.capabilities, []protocol.MCPResource{resource}, privKey)
	if err != nil {
		return fmt.Errorf("building agent card: %w", err)
	}

	return outputCard(card, cfg.outputFormat)
}

// outputCard prints an agent card in the requested format
func outputCard(card *protocol.AgentCard, format string) error {
	if format == "json" {
		return json.NewEncoder(os.Stdout).Encode(card)
	}

	// Default human-readable format
	data, err := json.MarshalIndent(card, "", "  ")
	if err != nil {
		return fmt.Errorf("formatting card: %w", err)
	}
	fmt.Println(string(data))
	return nil
}
