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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/spf13/cobra"

	samnet "sam/pkg/net"
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
	cmd.Flags().BoolVar(&cfg.meshWatch, "watch", false, "watch for newly discovered agents and append them live")
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

	if cfg.meshWatch {
		return runMeshGetAgentsWatch(parent, cfg, format, node)
	}

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

func runMeshGetAgentsWatch(parent context.Context, cfg *runConfig, format outputFormat, node samnet.Node) error {
	watchManager, err := newInventoryWatchManager(node, cfg.federation)
	if err != nil {
		return fmt.Errorf("creating inventory watch manager: %w", err)
	}
	defer func() {
		if closeErr := watchManager.Close(); closeErr != nil {
			slog.Warn("closing inventory watch manager", "err", closeErr)
		}
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.sam/watch/inventory" {
			http.NotFound(w, r)
			return
		}
		watchManager.ServeInventoryWatch(w, r)
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(parent, http.MethodGet, server.URL+"/.sam/watch/inventory", nil)
	if err != nil {
		return fmt.Errorf("building watch request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("opening watch stream: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("watch stream failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	discoverer, err := newAgentDiscoverer(node, cfg.federation, cfg.dhtCardMaxAge)
	if err != nil {
		return fmt.Errorf("creating informer discoverer: %w", err)
	}
	informer, err := samnet.NewLocalInformer(node, cfg.federation, samnet.WithInformerDiscoverer(discoverer))
	if err != nil {
		return fmt.Errorf("creating local informer: %w", err)
	}
	informer.Start(parent)

	if format == outputTable {
		if err := printAgentsTableHeader(os.Stdout); err != nil {
			return err
		}
	}

	seen := map[string]struct{}{}
	return consumeInventorySSE(resp.Body, func(evt samnet.AgentWatchEvent) error {
		if evt.Type != samnet.AgentWatchEventAdded || len(evt.Card) == 0 {
			return nil
		}
		card, err := decodeAgentCardRaw(evt.Card)
		if err != nil {
			return nil
		}
		if _, ok := seen[card.PeerID]; ok {
			return nil
		}
		seen[card.PeerID] = struct{}{}

		latencyByPeer := map[string]time.Duration{}
		if id, err := peer.Decode(card.PeerID); err == nil {
			latencyByPeer[card.PeerID] = node.Host().Peerstore().LatencyEWMA(id)
		}
		rows := toAgentRows([]*protocol.AgentCard{card}, latencyByPeer)
		if format == outputJSON {
			enc := json.NewEncoder(os.Stdout)
			return enc.Encode(rows[0])
		}
		return printAgentRows(os.Stdout, rows)
	})
}

func consumeInventorySSE(body io.Reader, onEvent func(samnet.AgentWatchEvent) error) error {
	scanner := bufio.NewScanner(body)
	var eventName string
	var dataLines []string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if strings.EqualFold(eventName, "HEARTBEAT") {
				eventName = ""
				dataLines = nil
				continue
			}
			if len(dataLines) > 0 {
				var evt samnet.AgentWatchEvent
				if err := json.Unmarshal([]byte(strings.Join(dataLines, "\n")), &evt); err != nil {
					return fmt.Errorf("decoding watch event: %w", err)
				}
				if evt.Type == "" {
					evt.Type = samnet.AgentWatchEventType(eventName)
				}
				if err := onEvent(evt); err != nil {
					return err
				}
			}
			eventName = ""
			dataLines = nil
			continue
		}
		if strings.HasPrefix(line, "event: ") {
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event: "))
			continue
		}
		if strings.HasPrefix(line, "data: ") {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}
