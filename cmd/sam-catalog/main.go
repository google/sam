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
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/catalog"
	"github.com/spf13/cobra"
)

var (
	nodeURL        string
	nodeToken      string
	bindAddr       string
	ownURL         string
	rewalkInterval time.Duration
	sweepInterval  time.Duration
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sam-catalog",
		Short: "SAM service catalog — aggregates and exposes service discoveries via MCP",
		RunE:  run,
	}

	rootCmd.Flags().StringVar(&nodeURL, "node-url", "", "sam-node sidecar base URL (e.g. http://127.0.0.1:8080)")
	rootCmd.Flags().StringVar(&nodeToken, "node-token", "", "Bearer token for sam-node sidecar API")
	rootCmd.Flags().StringVar(&bindAddr, "bind-addr", "127.0.0.1:0", "Catalog MCP listen address")
	rootCmd.Flags().StringVar(&ownURL, "own-url", "", "URL the node proxies to this catalog (default: http://<bind-addr>)")
	rootCmd.Flags().DurationVar(&rewalkInterval, "rewalk-interval", 3*time.Minute, "Interval between full bootstrap re-walks")
	rootCmd.Flags().DurationVar(&sweepInterval, "sweep-interval", 1*time.Minute, "Interval between TTL sweeps")

	_ = rootCmd.MarkFlagRequired("node-url")
	_ = rootCmd.MarkFlagRequired("node-token")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, _ []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	store := catalog.New()

	// Start MCP HTTP server.
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", bindAddr, err)
	}
	actualAddr := ln.Addr().String()
	log.Printf("catalog MCP on %s", actualAddr)

	srv := &http.Server{
		Handler:           newCatalogMCPHandler(store),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("catalog HTTP server error: %v", err)
		}
	}()

	if ownURL == "" {
		ownURL = "http://" + actualAddr
	}

	nc := newNodeClient(nodeURL, nodeToken)

	// Subscribe before snapshot to avoid missing announces during bootstrap.
	go func() {
		if err := nc.tail(ctx, store); err != nil && ctx.Err() == nil {
			log.Printf("tail exited: %v", err)
		}
	}()

	// Initial snapshot.
	if err := nc.bootstrap(ctx, store, []api.ServiceType{
		api.ServiceType_SERVICE_TYPE_MCP,
		api.ServiceType_SERVICE_TYPE_INFERENCE,
	}); err != nil {
		log.Printf("bootstrap warning: %v", err)
	}

	// Register this catalog as a service so others can discover it.
	if err := registerSelf(ctx, nodeURL, nodeToken, ownURL); err != nil {
		log.Printf("registerSelf warning: %v", err)
	}

	go runSweeper(ctx, store, sweepInterval)
	go runRewalk(ctx, nc, store, rewalkInterval)

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	return nil
}
