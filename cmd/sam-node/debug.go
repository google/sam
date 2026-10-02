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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/sam/internal/node"
	"github.com/spf13/cobra"
)

// newDebugCmd groups the operator diagnostics served by a running node's
// /debug endpoints, reached over its Unix socket so no token is involved.
func newDebugCmd() *cobra.Command {
	debugCmd := &cobra.Command{
		Use:   "debug",
		Short: "Diagnostics for a running node, over its Unix socket",
	}
	debugCmd.PersistentFlags().StringVar(&socketPathFlag, "socket-path", "", "Unix socket of the running node (defaults to <data-dir>/"+node.DefaultSocketName+")")

	debugCmd.AddCommand(
		newDebugGetCmd("mesh-info", "Show connected peers, DHT size, and the router peer ID", "/debug/mesh-info"),
		newDebugGetCmd("network-info", "Show listener and announced addresses", "/debug/network-info"),
		newDebugGetCmd("token-info", "Show the local auth token's expiration and status", "/debug/token-info"),
		newDebugGetCmd("logs", "Show the last few lines of the node's log output", "/debug/logs"),
	)

	debugCmd.AddCommand(&cobra.Command{
		Use:          "connectivity [peer-id]",
		Short:        "Ping the SAM router, or a specific peer",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "/debug/connectivity"
			if len(args) == 1 {
				path += "?peer_id=" + url.QueryEscape(args[0])
			}
			return debugRequest(cmd, http.MethodGet, path, nil)
		},
	})

	debugCmd.AddCommand(&cobra.Command{
		Use:          "connect-peer <multiaddr>",
		Short:        "Connect the node to a peer by its full multiaddress",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := json.Marshal(map[string]string{"peer_addr": args[0]})
			if err != nil {
				return err
			}
			return debugRequest(cmd, http.MethodPost, "/debug/connect-peer", bytes.NewReader(body))
		},
	})

	return debugCmd
}

// newDebugGetCmd builds a no-argument subcommand that GETs one /debug endpoint.
func newDebugGetCmd(use, short, path string) *cobra.Command {
	return &cobra.Command{
		Use:          use,
		Short:        short,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return debugRequest(cmd, http.MethodGet, path, nil)
		},
	}
}

// debugRequest performs one request against the node's Unix socket and prints
// the JSON response.
func debugRequest(cmd *cobra.Command, method, path string, body io.Reader) error {
	socketPath := resolveSocketPath(cmd)
	if socketPath == "" {
		return fmt.Errorf("no Unix socket configured (--socket-path is empty); sam-node debug needs the node to serve one")
	}
	req, err := http.NewRequestWithContext(cmd.Context(), method, "http://localhost"+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := socketClient(socketPath, 30*time.Second).Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the node on %s (is it running with a socket?): %w", socketPath, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	fmt.Println(strings.TrimSpace(string(data)))
	return nil
}

// socketClient returns an HTTP client that dials the node's Unix socket; the
// URL host is ignored.
func socketClient(path string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", path)
			},
		},
	}
}
