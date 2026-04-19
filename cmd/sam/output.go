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
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"sam/pkg/protocol"
)

// outputFormat controls how command results are rendered.
type outputFormat string

const (
	outputTable outputFormat = "table"
	outputJSON  outputFormat = "json"
)

// parseOutputFormat validates and normalises the -o flag value.
func parseOutputFormat(s string) (outputFormat, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "table", "":
		return outputTable, nil
	case "json":
		return outputJSON, nil
	default:
		return "", fmt.Errorf("unsupported output format %q: must be table or json", s)
	}
}

// agentRow is the flat representation used for both table and JSON output.
type agentRow struct {
	PeerID     string    `json:"peer_id"`
	Identity   string    `json:"identity"`
	Capability string    `json:"capability"`
	Latency    string    `json:"latency"`
	IssuedAt   time.Time `json:"issued_at"`
}

func toAgentRows(cards []*protocol.AgentCard, latencyByPeer map[string]time.Duration) []agentRow {
	rows := make([]agentRow, 0, len(cards))
	for _, c := range cards {
		identity := "unknown"
		if c.Vouch != nil {
			switch {
			case strings.TrimSpace(c.Vouch.Name()) != "":
				identity = c.Vouch.Name()
			case strings.TrimSpace(c.Vouch.Email()) != "":
				identity = c.Vouch.Email()
			case strings.TrimSpace(c.Vouch.Subject) != "":
				identity = c.Vouch.Subject
			case strings.TrimSpace(c.Vouch.Issuer) != "":
				identity = c.Vouch.Issuer
			}
		}
		caps := c.CapabilityNames()
		capability := ""
		if len(caps) > 0 {
			capability = caps[0]
		}
		latency := "n/a"
		if d, ok := latencyByPeer[c.PeerID]; ok {
			latency = d.Round(time.Millisecond).String()
		}
		rows = append(rows, agentRow{
			PeerID:     c.PeerID,
			Identity:   identity,
			Capability: capability,
			Latency:    latency,
			IssuedAt:   c.IssuedAt,
		})
	}
	return rows
}

// printAgents writes agent cards to w in the requested format.
func printAgents(w io.Writer, cards []*protocol.AgentCard, format outputFormat, latencyByPeer map[string]time.Duration) error {
	rows := toAgentRows(cards, latencyByPeer)
	switch format {
	case outputJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	default:
		return printAgentsTable(w, rows)
	}
}

func printAgentsTable(w io.Writer, rows []agentRow) error {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(tw, "PEER ID\tIDENTITY\tCAPABILITY\tLATENCY\tISSUED AT")
	for _, r := range rows {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			truncate(r.PeerID, 20),
			r.Identity,
			r.Capability,
			r.Latency,
			r.IssuedAt.Format(time.RFC3339),
		)
	}
	return tw.Flush()
}

func printAgentsTableHeader(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(tw, "PEER ID\tIDENTITY\tCAPABILITY\tLATENCY\tISSUED AT")
	return tw.Flush()
}

func printAgentRows(w io.Writer, rows []agentRow) error {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	for _, r := range rows {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			truncate(r.PeerID, 20),
			r.Identity,
			r.Capability,
			r.Latency,
			r.IssuedAt.Format(time.RFC3339),
		)
	}
	return tw.Flush()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
