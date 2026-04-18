package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/spf13/cobra"

	"sam/pkg/protocol"
)

func newMeshGetAgentsCmd(cfg *runConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agents",
		Short: "List agent cards visible in the mesh",
		Long: `List agent cards visible in the SAM mesh.

With no filter the command queries every currently-connected peer for its
AgentCard. Use --capability to narrow the result to agents that advertise a
specific skill via DHT discovery.

Examples:
  sam mesh get agents -o json
  sam mesh get agents --capability agent.summarize
  sam mesh get agents --capability agent.chat -o json | jq '.[].peer_id'`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMeshGetAgents(cmd.Context(), cfg)
		},
	}
	cmd.Flags().StringVar(&cfg.capability, "capability", "",
		"filter by capability (DHT discovery); omit to list all connected agents")
	cmd.Flags().StringVar(&cfg.skill, "skill", "", "alias of --capability")
	cmd.Flags().DurationVar(&cfg.discoverTimeout, "timeout", 10*time.Second,
		"how long to wait for DHT discovery when --capability is set")
	cmd.Flags().DurationVar(&cfg.dhtCardMaxAge, "dht-card-max-age", 15*time.Minute,
		"maximum accepted age for DHT-fetched cards (<=0 disables freshness check)")
	return cmd
}

func runMeshGetAgents(parent context.Context, cfg *runConfig) error {
	format, err := parseOutputFormat(cfg.outputFormat)
	if err != nil {
		return err
	}

	node, err := buildNode(cfg)
	if err != nil {
		return err
	}
	if err := node.Start(parent); err != nil {
		return fmt.Errorf("starting node: %w", err)
	}
	defer func() { _ = node.Stop(context.Background()) }()

	svc, err := protocol.NewDiscoveryService(node, protocol.WithMaxDHTCardAge(cfg.dhtCardMaxAge))
	if err != nil {
		return fmt.Errorf("creating discovery service: %w", err)
	}

	ctx, cancel := context.WithTimeout(parent, cfg.discoverTimeout)
	defer cancel()

	filter := cfg.capability
	if filter == "" {
		filter = cfg.skill
	}

	var cards []*protocol.AgentCard
	if filter != "" {
		// DHT-based capability-filtered discovery.
		cards, err = svc.Discover(ctx, filter)
	} else {
		// List AgentCards from all currently-connected peers.
		cards, err = svc.DiscoverAll(ctx)
	}
	if err != nil {
		return fmt.Errorf("discovering agents: %w", err)
	}

	latencyByPeer := map[string]time.Duration{}
	for _, c := range cards {
		if id, decodeErr := peer.Decode(c.PeerID); decodeErr == nil {
			latencyByPeer[c.PeerID] = node.Host().Peerstore().LatencyEWMA(id)
		}
	}

	return printAgents(os.Stdout, cards, format, latencyByPeer)
}
