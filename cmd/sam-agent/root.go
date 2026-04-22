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
	"log/slog"
	"os"
	"time"

	logging "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
)

// runConfig holds all flag values shared across subcommands.
type runConfig struct {
	// Node flags (persistent — available to every subcommand).
	listenAddrs  []string
	dhtMode      string
	withRelay    bool
	userAgent    string
	runFor       time.Duration
	hub          string
	identityPath string
	debug        bool

	// sam up
	tunnelHTTPEndpoint string

	// sam publish (shared by card and mcp subcommands)
	capabilities   []string
	skill          string
	resourceName   string
	resourceKind   string
	resourceEP     string
	resourceDesc   string
	republishEvery time.Duration

	// sam publish mcp
	mcpPort int

	// sam mesh get
	outputFormat    string
	capability      string
	discoverTimeout time.Duration
	dhtCardMaxAge   time.Duration
	meshWatch       bool

	// sam call
	callMessage string
	callBiscuit string
	callAmount  int64
	callAsset   string
	callNonce   string
	callTimeout time.Duration

	// sam proxy
	proxyPort      int
	proxyTargetHdr string
	proxyBiscuit   string
	proxyTimeout   time.Duration

	// dry-run modes: "", "client", "server"
	dryRun string
}

const defaultFederationID = "default"

// newRootCmd builds the top-level "sam-agent" command and attaches subcommands.
func newRootCmd(cfg *runConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sam-agent",
		Short: "SAM agent runtime and mesh CLI",
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return applyLogging(cfg.debug)
		},
	}

	// Persistent flags visible to every subcommand.
	pf := cmd.PersistentFlags()
	pf.StringSliceVar(&cfg.listenAddrs, "listen", []string{"/ip4/0.0.0.0/udp/0/quic-v1"}, "libp2p listen multiaddrs")
	pf.StringVar(&cfg.dhtMode, "dht-mode", "client", "DHT mode: client|server|auto")
	pf.BoolVar(&cfg.withRelay, "relay-service", false, "enable relay service")
	pf.StringVar(&cfg.userAgent, "user-agent", "sam/0.1.0", "libp2p user-agent")
	pf.DurationVar(&cfg.runFor, "run-for", 0, "optional duration before graceful shutdown (0 = wait for signal)")
	pf.StringVar(&cfg.hub, "hub", "", "OIDC hub URL for passport issuance and identity login")
	pf.StringVar(&cfg.identityPath, "identity", "", "path to PEM-encoded Ed25519 private key (generated and saved if absent)")
	pf.BoolVar(&cfg.debug, "debug", false, "enable debug logging (slog + libp2p subsystems)")

	cmd.AddCommand(newUpCmd(cfg))
	cmd.AddCommand(newPublishCmd(cfg))
	cmd.AddCommand(newMeshCmd(cfg))
	cmd.AddCommand(newCallCmd(cfg))
	cmd.AddCommand(newProxyCmd(cfg))
	cmd.AddCommand(newIdentityCmd(cfg))
	cmd.AddCommand(newInspectCmd(cfg))
	return cmd
}

// applyLogging configures the default slog handler and, when debug is true,
// sets every libp2p/IPFS subsystem logger to DEBUG as well.
func applyLogging(debug bool) error {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
		if err := logging.SetLogLevel("*", "debug"); err != nil {
			slog.Warn("could not set libp2p log level", "err", err)
		}
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	return nil
}
