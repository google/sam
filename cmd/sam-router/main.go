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
	"os"
	"time"

	"github.com/google/sam/internal/router"
	golog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
)

var (
	controlPlaneURL    string
	listenAddrs        []string
	externalAddrs      []string
	keysSyncInterval   time.Duration
	leaseRenewInterval time.Duration
	oidcToken          string
	jwtPath            string
	keysPath           string
	allowLoopback      bool
	logLevel           string
)

var logger = golog.Logger("sam-router-cli")

func main() {
	rootCmd := &cobra.Command{
		Use:   "sam-router",
		Short: "Sovereign Agent Mesh - libp2p Router Node",
		Run: func(cmd *cobra.Command, args []string) {
			// Initialize logging
			if os.Getenv("LOG_FORMAT") == "json" {
				_ = os.Setenv("GOLOG_LOG_FMT", "json")
			}
			golog.SetAllLoggers(golog.LevelInfo)
			if logLevel != "" {
				lvl, err := golog.LevelFromString(logLevel)
				if err == nil {
					golog.SetAllLoggers(lvl)
				}
			}

			opts := router.Options{
				ControlPlaneURL:    controlPlaneURL,
				ListenAddrs:        listenAddrs,
				ExternalAddrs:      externalAddrs,
				KeysSyncInterval:   keysSyncInterval,
				LeaseRenewInterval: leaseRenewInterval,
				OIDCToken:          oidcToken,
				JWTPath:            jwtPath,
				KeysDBPath:         keysPath,
				AllowLoopback:      allowLoopback,
			}

			r, err := router.NewRouter(cmd.Context(), opts)
			if err != nil {
				logger.Fatalf("Failed to initialize router: %v", err)
			}
			defer func() {
				if err := r.Close(); err != nil {
					logger.Errorf("Failed to stop router: %v", err)
				}
			}()

			if err := r.Start(); err != nil {
				logger.Fatalf("Failed to start router: %v", err)
			}

			<-cmd.Context().Done()
		},
	}

	rootCmd.Flags().StringVar(&controlPlaneURL, "control-plane", "http://127.0.0.1:8080", "Control Plane web service URL")
	rootCmd.Flags().StringSliceVar(&listenAddrs, "listen", []string{"/ip4/0.0.0.0/tcp/5001", "/ip6/::/tcp/5001"}, "libp2p Listen Addresses")
	rootCmd.Flags().StringSliceVar(&externalAddrs, "external-addr", []string{}, "External addresses to announce to control plane")
	rootCmd.Flags().DurationVar(&keysSyncInterval, "keys-sync-interval", 5*time.Minute, "Key synchronization polling interval")
	rootCmd.Flags().DurationVar(&leaseRenewInterval, "lease-renew-interval", 300*time.Second, "Lease renewal registration interval")
	rootCmd.Flags().StringVar(&oidcToken, "oidc-token", "", "OIDC ID token or bootstrap secret token for enrollment")
	rootCmd.Flags().StringVar(&jwtPath, "jwt-path", "", "Path to file containing OIDC JWT token")
	rootCmd.Flags().StringVar(&keysPath, "keys-path", "router.key", "Path to save/load persistent private key")
	rootCmd.Flags().BoolVar(&allowLoopback, "allow-loopback", false, "Allow loopback and link-local addresses for discovery")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
