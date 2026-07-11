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
	"strings"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/controlplane"
	"github.com/google/sam/internal/storage"
	golog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
)

var (
	bindAddress           string
	dbDriver              string
	dbDSN                 string
	oidcIssuer            string
	allowedAudiencesFlag  string
	policyFile            string
	keyRotationInterval   time.Duration
	keyGracePeriod        time.Duration
	leaseDuration         time.Duration
	adminToken            string
	insecureSkipTLSVerify bool
	logLevel              string
	autoApproveEnrollment bool
)

var logger = golog.Logger("sam-control-plane-cli")

func main() {
	rootCmd := &cobra.Command{
		Use:   "sam-control-plane",
		Short: "Sovereign Agent Mesh - Control Plane",
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

			if oidcIssuer == "" {
				logger.Fatalf("OIDC issuer is required (use --issuer flag)")
			}

			var auds []string
			for _, aud := range strings.Split(allowedAudiencesFlag, ",") {
				aud = strings.TrimSpace(aud)
				if aud != "" {
					auds = append(auds, aud)
				}
			}
			if len(auds) == 0 {
				auds = []string{api.DefaultAudience}
			}

			// Open DB Store
			store, err := storage.NewSQLStore(dbDriver, dbDSN)
			if err != nil {
				logger.Fatalf("Failed to initialize database store: %v", err)
			}
			defer func() {
				if err := store.Close(); err != nil {
					logger.Errorf("Failed to close database: %v", err)
				}
			}()

			opts := controlplane.Options{
				ListenAddr:            bindAddress,
				DriverName:            dbDriver,
				DataSourceName:        dbDSN,
				OIDCIssuer:            oidcIssuer,
				AllowedAudiences:      auds,
				LeaseDuration:         leaseDuration,
				KeyRotationInterval:   keyRotationInterval,
				KeyGracePeriod:        keyGracePeriod,
				InsecureSkipTLSVerify: insecureSkipTLSVerify,
				PolicyPath:            policyFile,
				BiscuitTimeout:        10 * time.Second,
				AdminToken:            adminToken,
				AutoApproveEnrollment: autoApproveEnrollment,
			}

			srv, err := controlplane.NewServer(opts, store)
			if err != nil {
				logger.Fatalf("Failed to create control plane server: %v", err)
			}
			defer func() {
				if err := srv.Close(); err != nil {
					logger.Errorf("Failed to stop control plane: %v", err)
				}
			}()

			if err := srv.Start(); err != nil {
				logger.Fatalf("Failed to start control plane: %v", err)
			}

			logger.Infof("SAM Control Plane Online on %s", bindAddress)
			<-cmd.Context().Done()
		},
	}

	rootCmd.Flags().StringVar(&bindAddress, "bind-address", "0.0.0.0:8080", "Address to listen on for web API services")
	rootCmd.PersistentFlags().StringVar(&dbDriver, "db-driver", "sqlite", "Database driver (sqlite or postgres)")
	rootCmd.PersistentFlags().StringVar(&dbDSN, "db-dsn", "control-plane.db", "Database DSN/Connection URL")
	rootCmd.Flags().StringVar(&oidcIssuer, "issuer", "", "OIDC Issuer URL (comma-separated)")
	rootCmd.Flags().StringVar(&allowedAudiencesFlag, "allowed-audiences", api.DefaultAudience, "Comma-separated list of allowed OIDC audiences")
	rootCmd.Flags().StringVar(&policyFile, "policy-file", "policies.yaml", "Path to policies.yaml (bootstrapping only)")
	rootCmd.Flags().DurationVar(&keyRotationInterval, "key-rotation-interval", 24*time.Hour, "Key rotation interval (e.g. 24h). 0 disables rotation.")
	rootCmd.Flags().DurationVar(&keyGracePeriod, "key-grace-period", 1*time.Hour, "Key grace period for rotated keys.")
	rootCmd.Flags().DurationVar(&leaseDuration, "lease-duration", 15*time.Minute, "Router lease registration TTL.")
	rootCmd.Flags().StringVar(&adminToken, "admin-token", "", "Token for authenticating policy REST API requests")
	rootCmd.Flags().BoolVar(&insecureSkipTLSVerify, "insecure-skip-tls-verify", false, "Skip TLS verification for OIDC providers")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().BoolVar(&autoApproveEnrollment, "auto-approve-enrollment", false, "Auto-approve valid bootstrap token enrollment requests")

	adminCmd := &cobra.Command{
		Use:   "admin",
		Short: "Administrative operations",
	}

	var peerIDFlag string
	banCmd := &cobra.Command{
		Use:   "ban",
		Short: "Ban a node peer ID",
		Run: func(cmd *cobra.Command, args []string) {
			store, err := storage.NewSQLStore(dbDriver, dbDSN)
			if err != nil {
				logger.Fatalf("Failed to initialize database store: %v", err)
			}
			defer store.Close() //nolint:errcheck
			if err := store.SetNodeBanned(cmd.Context(), peerIDFlag, true); err != nil {
				logger.Fatalf("Failed to ban node: %v", err)
			}
			logger.Infof("Successfully banned node %s", peerIDFlag)
		},
	}
	banCmd.Flags().StringVar(&peerIDFlag, "peer", "", "Node Peer ID to ban")
	_ = banCmd.MarkFlagRequired("peer")

	unbanCmd := &cobra.Command{
		Use:   "unban",
		Short: "Unban a node peer ID",
		Run: func(cmd *cobra.Command, args []string) {
			store, err := storage.NewSQLStore(dbDriver, dbDSN)
			if err != nil {
				logger.Fatalf("Failed to initialize database store: %v", err)
			}
			defer store.Close() //nolint:errcheck
			if err := store.SetNodeBanned(cmd.Context(), peerIDFlag, false); err != nil {
				logger.Fatalf("Failed to unban node: %v", err)
			}
			logger.Infof("Successfully unbanned node %s", peerIDFlag)
		},
	}
	unbanCmd.Flags().StringVar(&peerIDFlag, "peer", "", "Node Peer ID to unban")
	_ = unbanCmd.MarkFlagRequired("peer")

	adminCmd.AddCommand(banCmd, unbanCmd)
	rootCmd.AddCommand(adminCmd)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
