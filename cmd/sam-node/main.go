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
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/sam/api"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
)

var (
	hubAddr     string
	listenAddrs []string

	jwtFlag               string
	jwtPathFlag           string
	clientIDFlag          string
	clientSecretFlag      string
	tokenURLFlag          string
	hubPublicKeyFlag      string
	mcpSocketFlag         string
	meshFlag              string
	discoveryIntervalFlag string
	enableRelayFlag       bool
	logLevelFlag          string
)

var logger = golog.Logger("sam-node")

func main() {
	rootCmd := &cobra.Command{
		Use:   "sam-node",
		Short: "Sovereign Agent Mesh Node",
	}

	// RUN COMMAND: Start the Mesh
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Start the sovereign mesh node",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()

			// Initialize logging
			golog.SetAllLoggers(golog.LevelInfo)
			if logLevelFlag != "" {
				lvl, err := golog.LevelFromString(logLevelFlag)
				if err == nil {
					golog.SetAllLoggers(lvl)
				}
			}

			dataDir, err := GetDataDir()
			if err != nil {
				logger.Fatalf("Failed to get data dir: %v", err)
			}
			store, err := NewStore(dataDir)
			if err != nil {
				logger.Fatalf("Failed to open store: %v", err)
			}
			defer func() {
				if err := store.Close(); err != nil {
					logger.Error("closing store: %v", err)
				}
			}()

			var hubPubKey ed25519.PublicKey
			var hubAddrs []multiaddr.Multiaddr

			storedPubKey, storedAddrs, _ := store.LoadHubConfig()
			if len(storedPubKey) > 0 {
				hubPubKey = storedPubKey
				for _, addrStr := range storedAddrs {
					ma, _ := multiaddr.NewMultiaddr(addrStr)
					hubAddrs = append(hubAddrs, ma)
				}
			}

			if hubPublicKeyFlag != "" {
				pubBytes, err := hex.DecodeString(hubPublicKeyFlag)
				if err != nil {
					logger.Fatalf("Invalid hub public key: %v", err)
				}
				hubPubKey = pubBytes
			}

			var node *SamNode

			var jwtStr string

			if jwtFlag != "" {
				jwtStr = jwtFlag
			} else if jwtPathFlag != "" {
				data, err := os.ReadFile(jwtPathFlag)
				if err != nil {
					logger.Fatalf("Failed to read JWT file: %v", err)
				}
				jwtStr = strings.TrimSpace(string(data))
			} else if tokenURLFlag != "" {
				logger.Info("Fetching JWT via OIDC Client Credentials...")
				dummyNode := &SamNode{}
				var err error
				jwtStr, err = dummyNode.FetchJWT(context.Background(), tokenURLFlag, clientIDFlag, clientSecretFlag)
				if err != nil {
					logger.Fatalf("Failed to fetch JWT: %v", err)
				}
			}

			if jwtStr == "" {
				token, _ := store.LoadIdentity()
				if token == "" {
					logger.Fatal("No JWT or stored identity found. Cannot authenticate.")
				}
				fmt.Println("Using stored identity.")

				if len(hubPubKey) == 0 {
					logger.Fatal("Hub public key not found in store and not provided. Cannot verify peers.")
				}
				priv := getOrGenerateKey(store)
				node, err = NewSamNode(context.Background(), priv, hubPubKey, hubAddrs, store, meshFlag, discoveryIntervalFlag, listenAddrs, enableRelayFlag)
				if err != nil {
					logger.Fatalf("Failed to start mesh node: %v", err)
				}
			} else {
				var initHubAddrs []multiaddr.Multiaddr
				ma, err := multiaddr.NewMultiaddr(hubAddr)
				if err == nil {
					initHubAddrs = []multiaddr.Multiaddr{ma}
				} else {
					// Try parsing as host:port
					host, port, err := net.SplitHostPort(hubAddr)
					if err == nil {
						ip := net.ParseIP(host)
						var maddr multiaddr.Multiaddr
						if ip != nil {
							maddr, _ = multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%s", host, port))
						} else {
							maddr, _ = multiaddr.NewMultiaddr(fmt.Sprintf("/dns4/%s/tcp/%s", host, port))
						}
						initHubAddrs = []multiaddr.Multiaddr{maddr}
					} else {
						if len(hubAddrs) > 0 {
							initHubAddrs = hubAddrs
						} else {
							logger.Fatalf("Invalid hub address and no stored config: %v", err)
						}
					}
				}

				priv := getOrGenerateKey(store)
				node, err = NewSamNode(context.Background(), priv, nil, initHubAddrs, store, meshFlag, discoveryIntervalFlag, listenAddrs, enableRelayFlag)
				if err != nil {
					logger.Fatalf("Failed to initialize node for enrollment: %v", err)
				}

				err = node.Enroll(context.Background(), jwtStr)
				if err != nil {
					logger.Fatalf("Enrollment failed: %v", err)
				}

				storedPubKey, _, _ = store.LoadHubConfig()
				hubPubKey = storedPubKey

				node.HubPublicKey = hubPubKey
			}

			// Start renewal loop
			go func() {
				for {
					var renewAfter = 50 * time.Minute // Default fallback

					exp, err := node.Store.LoadIdentityExpiration()
					if err == nil && exp > 0 {
						expTime := time.Unix(exp, 0)
						duration := time.Until(expTime)
						// Renew 10 minutes before expiration if duration permits
						if duration > 15*time.Minute {
							renewAfter = duration - 10*time.Minute
						} else if duration > 0 {
							renewAfter = duration / 2 // half of remaining time
						} else {
							renewAfter = 1 * time.Minute // already expired or immediate
						}
					}

					fmt.Printf("[Auth] Next renewal in %v\n", renewAfter)
					timer := time.NewTimer(renewAfter)

					select {
					case <-ctx.Done():
						timer.Stop()
						return
					case <-timer.C:
						fmt.Println("Renewing enrollment...")
						var newJWT string
						if tokenURLFlag != "" {
							var err error
							newJWT, err = node.FetchJWT(ctx, tokenURLFlag, clientIDFlag, clientSecretFlag)
							if err != nil {
								fmt.Printf("Failed to fetch JWT for renewal: %v\n", err)
								continue
							}
						} else if jwtPathFlag != "" {
							data, err := os.ReadFile(jwtPathFlag)
							if err != nil {
								fmt.Printf("Failed to read JWT file for renewal: %v\n", err)
								continue
							}
							newJWT = strings.TrimSpace(string(data))
						} else {
							fmt.Println("No credentials available for renewal.")
							continue
						}

						if err := node.Enroll(ctx, newJWT); err != nil {
							fmt.Printf("Renewal enrollment failed: %v\n", err)
						} else {
							fmt.Println("Enrollment renewed successfully.")
						}
					}
				}
			}()

			node.Host.SetStreamHandler(AuthProtocolID, node.HandleAuthHandshake)

			// Start MCP Server
			mcpHandler := NewMCPHandler(node)
			go func() {
				socketPath := mcpSocketFlag
				if socketPath == "" {
					socketPath = filepath.Join(dataDir, "mcp.sock")
				}

				// Remove old socket file if it exists
				_ = os.Remove(socketPath)

				listener, err := net.Listen("unix", socketPath)
				if err != nil {
					logger.Errorf("Failed to listen on Unix socket %s: %v", socketPath, err)
					return
				}
				defer func() {
					if err := listener.Close(); err != nil {
						logger.Errorf("Failed to close listener: %v", err)
					}
				}()

				fmt.Printf("Starting MCP server on Unix socket %s\n", socketPath)
				if err := http.Serve(listener, mcpHandler); err != nil {
					logger.Errorf("MCP server error: %v", err)
				}
			}()

			fmt.Printf("SAM Node Online.\nPeerID: %s\nListening on: %v\n", node.Host.ID(), node.Host.Addrs())

			// Block forever
			<-ctx.Done()
			fmt.Println("Shutting down...")
		},
	}

	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to the mesh via interactive OIDC flow",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			dataDir, err := GetDataDir()
			if err != nil {
				logger.Fatalf("Failed to get data dir: %v", err)
			}
			store, err := NewStore(dataDir)
			if err != nil {
				logger.Fatalf("Failed to open store: %v", err)
			}
			defer func() {
				if err := store.Close(); err != nil {
					logger.Errorf("closing store: %v", err)
				}
			}()

			if tokenURLFlag == "" {
				logger.Fatal("--token-url is required for login")
			}

			dummyNode := &SamNode{Store: store}
			jwtStr, err := dummyNode.InteractiveLogin(ctx, tokenURLFlag)
			if err != nil {
				logger.Fatalf("Failed to get token: %v", err)
			}

			// Connect to Hub and Enroll
			var initHubAddrs []multiaddr.Multiaddr
			ma, err := multiaddr.NewMultiaddr(hubAddr)
			if err == nil {
				initHubAddrs = []multiaddr.Multiaddr{ma}
			} else {
				host, port, err := net.SplitHostPort(hubAddr)
				if err == nil {
					ip := net.ParseIP(host)
					var maddr multiaddr.Multiaddr
					if ip != nil {
						maddr, _ = multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%s", host, port))
					} else {
						maddr, _ = multiaddr.NewMultiaddr(fmt.Sprintf("/dns4/%s/tcp/%s", host, port))
					}
					initHubAddrs = []multiaddr.Multiaddr{maddr}
				} else {
					logger.Fatalf("Invalid hub address: %v", err)
				}
			}

			priv := getOrGenerateKey(store)
			node, err := NewSamNode(context.Background(), priv, nil, initHubAddrs, store, meshFlag, discoveryIntervalFlag, listenAddrs, enableRelayFlag)
			if err != nil {
				logger.Fatalf("Failed to initialize node for enrollment: %v", err)
			}

			err = node.Enroll(context.Background(), jwtStr)
			if err != nil {
				logger.Fatalf("Enrollment failed: %v", err)
			}

			fmt.Println("Login successful and identity stored.")
		},
	}

	// Configure Flags
	runCmd.Flags().StringSliceVar(&listenAddrs, "listen", []string{"/ip4/0.0.0.0/udp/5001/quic-v1", "/ip4/0.0.0.0/tcp/5002"}, "libp2p Listen Addrs")
	runCmd.Flags().StringVar(&jwtFlag, "jwt", "", "Pre-fetched JWT token")
	runCmd.Flags().StringVar(&jwtPathFlag, "jwt-path", "", "Path to file containing JWT token")
	runCmd.Flags().StringVar(&clientIDFlag, "client-id", os.Getenv("SAM_OIDC_ID"), "OIDC Client ID for M2M")
	runCmd.Flags().StringVar(&clientSecretFlag, "client-secret", os.Getenv("SAM_OIDC_SECRET"), "OIDC Client Secret for M2M")
	runCmd.Flags().StringVar(&hubPublicKeyFlag, "hub-public-key", "", "Hub Public Key (32-byte Hex)")
	runCmd.Flags().StringVar(&mcpSocketFlag, "mcp-socket", "", "Path to Unix domain socket for local MCP server (default: <datadir>/mcp.sock)")
	runCmd.Flags().StringVar(&meshFlag, "mesh", "public-mesh", "Mesh federation name")
	runCmd.Flags().StringVar(&discoveryIntervalFlag, "discovery-interval", "2s", "Polling interval for DHT discovery")
	runCmd.Flags().BoolVar(&enableRelayFlag, "enable-relay", false, "Allow this node to serve as a relay for others")
	runCmd.Flags().StringVar(&logLevelFlag, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&hubAddr, "hub", "http://localhost:8080", "Hub URL")
	rootCmd.PersistentFlags().StringVar(&tokenURLFlag, "token-url", "", "OIDC Token URL")

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(loginCmd)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[Signal] Received interrupt, shutting down...")
		cancel()
	}()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

// getOrGenerateKey retrieves a persistent private key or creates one if it's the first run
func getOrGenerateKey(s *Store) crypto.PrivKey {
	kb, _ := s.LoadKey()
	if len(kb) == 0 {
		fmt.Println("[Store] Generating new Peer Identity...")
		priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			logger.Fatalf("Failed to generate key: %v", err)
		}
		raw, _ := crypto.MarshalPrivateKey(priv)
		if err := s.SaveKey(raw); err != nil {
			logger.Fatalf("Failed to save key: %v", err)
		}
		return priv
	}
	priv, err := crypto.UnmarshalPrivateKey(kb)
	if err != nil {
		logger.Fatalf("Corrupt key in store: %v", err)
	}
	return priv
}

func (n *SamNode) Enroll(ctx context.Context, jwt string) error {
	if n.HubPeerID == "" {
		return fmt.Errorf("not connected to any hub")
	}

	s, err := n.Host.NewStream(ctx, n.HubPeerID, api.EnrollProtocolID)
	if err != nil {
		return fmt.Errorf("failed to open enroll stream: %v", err)
	}
	defer func() { _ = s.Close() }()

	req := &api.EnrollRequest{
		Jwt:    jwt,
		PeerId: n.Host.ID().String(),
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal enroll request: %v", err)
	}

	writer := msgio.NewVarintWriter(s)
	if err := writer.WriteMsg(data); err != nil {
		return fmt.Errorf("failed to write enroll request: %v", err)
	}

	reader := msgio.NewVarintReaderSize(s, 1024*64)
	respMsg, err := reader.ReadMsg()
	if err != nil {
		return fmt.Errorf("failed to read enroll response: %v", err)
	}
	defer reader.ReleaseMsg(respMsg)

	var resp api.EnrollResponse
	if err := proto.Unmarshal(respMsg, &resp); err != nil {
		return fmt.Errorf("failed to unmarshal enroll response: %v", err)
	}

	if resp.ErrorMessage != "" {
		return fmt.Errorf("enrollment failed: %s", resp.ErrorMessage)
	}

	if len(resp.BiscuitToken) == 0 {
		return fmt.Errorf("received empty biscuit token")
	}

	tokenStr := base64.StdEncoding.EncodeToString(resp.BiscuitToken)
	if err := n.Store.SaveIdentity(tokenStr); err != nil {
		return fmt.Errorf("failed to save identity: %v", err)
	}

	if err := n.Store.SaveIdentityExpiration(resp.Expiration); err != nil {
		return fmt.Errorf("failed to save identity expiration: %v", err)
	}

	if err := n.Store.SaveHubConfig(resp.HubPublicKey, resp.HubAddresses); err != nil {
		return fmt.Errorf("failed to save hub config: %v", err)
	}

	if len(resp.DatalogPolicies) > 0 {
		if err := n.Store.SavePolicies(resp.DatalogPolicies); err != nil {
			return fmt.Errorf("failed to save policies: %v", err)
		}
	}

	// Add known peers from response
	n.mu.Lock()
	for _, p := range resp.KnownPeers {
		n.knownPeers[p] = true
		fmt.Printf("[Enroll] Added known peer from hub: %s\n", p)
	}
	n.mu.Unlock()

	fmt.Println("Successfully enrolled and stored identity and hub config.")
	return nil
}
