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
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/sam/api"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultMeshName          = "public-mesh"
	DefaultDiscoveryInterval = "2s"
	DefaultHubURL            = "http://localhost:8080"
	DefaultConfigFile        = "sam-node.yaml"

	// Renewal timing defaults
	DefaultRenewalFallback = 50 * time.Minute
	RenewalBuffer          = 10 * time.Minute
	RenewalThreshold       = 15 * time.Minute
)

var (
	hubAddr     string
	listenAddrs []string

	jwtFlag               string
	jwtPathFlag           string
	clientIDFlag          string
	clientSecretFlag      string
	oidcIssuerFlag        string
	deviceAuthURLFlag     string
	audienceFlag          string
	hubPublicKeyFlag      string
	bindAddrFlag          string
	meshFlag              string
	discoveryIntervalFlag string
	enableRelayFlag       bool
	logLevelFlag          string
	configFile            string
	keyGracePeriodFlag    time.Duration
	dataDirFlag           string
	allowLoopbackFlag     bool

	apiTokenFlag string
	tlsCertFlag  string
	tlsKeyFlag   string
	tlsCAFlag    string
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

			store, err := NewStore(resolveDataDir())
			if err != nil {
				logger.Fatalf("Failed to open store: %v", err)
			}

			nodeConfig, err := LoadNodeConfig(configFile)
			if err != nil {
				logger.Fatalf("Failed to load node config: %v", err)
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
					ma, err := multiaddr.NewMultiaddr(addrStr)
					if err != nil {
						logger.Warnf("Failed to parse stored hub address %q: %v", addrStr, err)
						continue
					}
					hubAddrs = append(hubAddrs, ma)
				}
			}

			if hubPublicKeyFlag != "" {
				pubBytes, err := hex.DecodeString(strings.TrimSpace(hubPublicKeyFlag))
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
			} else if oidcIssuerFlag != "" {
				logger.Info("Discovering OIDC endpoints...")
				dummyNode := &SamNode{}
				tokenURL, err := dummyNode.DiscoverTokenURL(context.Background(), oidcIssuerFlag)
				if err != nil {
					logger.Fatalf("Failed to discover OIDC endpoints: %v", err)
				}
				logger.Info("Fetching JWT via OIDC Client Credentials...")
				jwtStr, err = dummyNode.FetchJWT(context.Background(), tokenURL, clientIDFlag, clientSecretFlag)
				if err != nil {
					logger.Fatalf("Failed to fetch JWT: %v", err)
				}
			}

			if jwtStr == "" {
				token, _ := store.LoadIdentity()
				if len(token) == 0 {
					logger.Fatal("No JWT or stored identity found. Cannot authenticate.")
				}
				logger.Infoln("Using stored identity.")

				if len(hubPubKey) == 0 {
					logger.Fatal("Hub public key not found in store and not provided. Cannot verify peers.")
				}
				priv := getOrGenerateKey(store)
				node, err = NewSamNode(context.Background(), priv, hubPubKey, hubAddrs, store, meshFlag, discoveryIntervalFlag, listenAddrs, enableRelayFlag, nodeConfig, keyGracePeriodFlag, allowLoopbackFlag)
				if err != nil {
					logger.Fatalf("Failed to start mesh node: %v", err)
				}
			} else {
				// We have a new JWT (from flag or interactive login), need to enroll
				var initHubAddrs []multiaddr.Multiaddr
				if !strings.HasPrefix(hubAddr, "http://") && !strings.HasPrefix(hubAddr, "https://") {
					ma, err := multiaddr.NewMultiaddr(hubAddr)
					if err == nil {
						initHubAddrs = []multiaddr.Multiaddr{ma}
					} else {
						// Try parsing as host:port
						host, port, err := net.SplitHostPort(hubAddr)
						if err == nil {
							ip := net.ParseIP(host)
							var maddr multiaddr.Multiaddr
							var parseErr error
							if ip != nil {
								maddr, parseErr = multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%s", host, port))
							} else {
								maddr, parseErr = multiaddr.NewMultiaddr(fmt.Sprintf("/dns4/%s/tcp/%s", host, port))
							}
							if parseErr != nil {
								logger.Fatalf("Failed to parse multiaddr: %v", parseErr)
							}
							initHubAddrs = []multiaddr.Multiaddr{maddr}
						} else {
							if len(hubAddrs) > 0 {
								initHubAddrs = hubAddrs
							} else {
								logger.Fatalf("Invalid hub address and no stored config: %v. You can use community maintained meshes like hub.sam-mesh.dev (Production) or bananas.sam-mesh.dev (Testnet)", err)
							}
						}
					}
				}

				priv := getOrGenerateKey(store)
				enrollCtx, enrollCancel := context.WithCancel(context.Background())
				node, err = NewSamNode(enrollCtx, priv, nil, initHubAddrs, store, meshFlag, discoveryIntervalFlag, listenAddrs, enableRelayFlag, nodeConfig, keyGracePeriodFlag, allowLoopbackFlag)
				if err != nil {
					enrollCancel()
					logger.Fatalf("Failed to initialize node for enrollment: %v", err)
				}

				err = node.Enroll(enrollCtx, jwtStr)
				if err != nil {
					if teardownErr := node.Teardown(); teardownErr != nil {
						logger.Errorf("Teardown failed during enrollment error cleanup: %v", teardownErr)
					}
					enrollCancel()
					logger.Fatalf("Enrollment failed: %v", err)
				}

				node.mu.Lock()
				enrollKnownPeers := make(map[string]bool)
				for k, v := range node.knownPeers {
					enrollKnownPeers[k] = v
				}
				node.mu.Unlock()

				if teardownErr := node.Teardown(); teardownErr != nil {
					logger.Errorf("Failed to teardown enrollment node: %v", teardownErr)
				}
				enrollCancel()

				storedPubKey, storedAddrs, _ := store.LoadHubConfig()
				hubPubKey = storedPubKey
				var newHubAddrs []multiaddr.Multiaddr
				for _, addrStr := range storedAddrs {
					ma, err := multiaddr.NewMultiaddr(addrStr)
					if err != nil {
						logger.Warnf("Failed to parse stored hub address %q: %v", addrStr, err)
						continue
					}
					newHubAddrs = append(newHubAddrs, ma)
				}

				node, err = NewSamNode(context.Background(), priv, hubPubKey, newHubAddrs, store, meshFlag, discoveryIntervalFlag, listenAddrs, enableRelayFlag, nodeConfig, keyGracePeriodFlag, allowLoopbackFlag)
				if err != nil {
					logger.Fatalf("Failed to start mesh node after enrollment: %v", err)
				}

				node.mu.Lock()
				for k, v := range enrollKnownPeers {
					if node.Host != nil && k == node.Host.ID().String() {
						continue
					}
					node.knownPeers[k] = v
				}
				node.mu.Unlock()
			}

			// Register static services from config
			if nodeConfig != nil && len(nodeConfig.Services) > 0 {
				if err := node.RegisterStaticServices(context.Background(), nodeConfig.Services); err != nil {
					logger.Fatalf("Failed to register static services: %v", err)
				}
			}

			// Start renewal loop
			node.StartRenewalLoop(ctx, oidcIssuerFlag, clientIDFlag, clientSecretFlag, jwtPathFlag)

			node.Host.SetStreamHandler(api.AuthProtocolID, node.HandleAuthHandshake)

			// Start Sidecar API Server (multiplexed with MCP)
			if err := startSidecarServer(node, bindAddrFlag, apiTokenFlag, tlsCertFlag, tlsKeyFlag, tlsCAFlag); err != nil {
				logger.Fatalf("Failed to start sidecar server: %v", err)
			}

			fmt.Printf("SAM Node Online.\nPeerID: %s\nListening on: %v\n", node.Host.ID(), node.Host.Addrs())

			// Block forever
			<-ctx.Done()
			fmt.Println("Shutting down...")
		},
	}

	joinCmd := &cobra.Command{
		Use:   "join [hub_url]",
		Short: "Join the Sovereign Agent Mesh hub",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			targetHub := ""
			if len(args) > 0 {
				targetHub = args[0]
			}

			if targetHub == "" {
				fmt.Print("No hub URL provided. Do you want to join the default community testing network (https://bananas.sam-mesh.dev)? [y/N]: ")
				reader := bufio.NewReader(os.Stdin)
				response, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println("\nAborting: failed to read input.")
					return
				}
				response = strings.ToLower(strings.TrimSpace(response))
				if response != "y" && response != "yes" {
					fmt.Println("Aborting join operation.")
					return
				}
				targetHub = "https://bananas.sam-mesh.dev"
			}

			if !strings.HasPrefix(targetHub, "http://") && !strings.HasPrefix(targetHub, "https://") {
				targetHub = "https://" + targetHub
			}
			targetHub = strings.TrimSuffix(targetHub, "/")

			store, err := NewStore(resolveDataDir())
			if err != nil {
				logger.Fatalf("Failed to open store: %v", err)
			}

			nodeConfig, err := LoadNodeConfig(configFile)
			if err != nil {
				logger.Fatalf("Failed to load node config: %v", err)
			}
			defer func() {
				if err := store.Close(); err != nil {
					logger.Errorf("closing store: %v", err)
				}
			}()

			dummyNode := &SamNode{Store: store}

			fmt.Printf("Discovering hub info from %s...\n", targetHub)
			hubInfo, err := dummyNode.DiscoverHubInfo(ctx, targetHub)
			if err != nil {
				logger.Fatalf("Failed to discover hub info: %v", err)
			}

			fmt.Printf("OIDC Issuer discovered: %s\n", hubInfo.OidcIssuer)
			fmt.Printf("Client ID discovered: %s\n", hubInfo.ClientId)

			logger.Info("Discovering OIDC endpoints...")
			tokenURL, deviceAuthURL, err := dummyNode.DiscoverEndpoints(ctx, hubInfo.OidcIssuer)
			if err != nil {
				logger.Fatalf("Failed to discover OIDC endpoints: %v", err)
			}

			jwtStr, err := dummyNode.InteractiveLogin(ctx, deviceAuthURL, tokenURL, hubInfo.ClientId, hubInfo.Audience)
			if err != nil {
				logger.Fatalf("Failed to get token: %v", err)
			}

			// Override global hubAddr with targetHub for enrollment
			hubAddr = targetHub

			// Connect to Hub and Enroll
			var initHubAddrs []multiaddr.Multiaddr
			if !strings.HasPrefix(hubAddr, "http://") && !strings.HasPrefix(hubAddr, "https://") {
				ma, err := multiaddr.NewMultiaddr(hubAddr)
				if err == nil {
					initHubAddrs = []multiaddr.Multiaddr{ma}
				} else {
					host, port, err := net.SplitHostPort(hubAddr)
					if err == nil {
						ip := net.ParseIP(host)
						var maddr multiaddr.Multiaddr
						var parseErr error
						if ip != nil {
							maddr, parseErr = multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%s", host, port))
						} else {
							maddr, parseErr = multiaddr.NewMultiaddr(fmt.Sprintf("/dns4/%s/tcp/%s", host, port))
						}
						if parseErr != nil {
							logger.Fatalf("Failed to parse multiaddr: %v", parseErr)
						}
						initHubAddrs = []multiaddr.Multiaddr{maddr}
					} else {
						logger.Fatalf("Invalid hub address: %v", err)
					}
				}
			}

			priv := getOrGenerateKey(store)
			node, err := NewSamNode(context.Background(), priv, nil, initHubAddrs, store, meshFlag, discoveryIntervalFlag, []string{"/ip4/0.0.0.0/udp/0/quic-v1", "/ip4/0.0.0.0/tcp/0"}, enableRelayFlag, nodeConfig, keyGracePeriodFlag, allowLoopbackFlag)
			if err != nil {
				logger.Fatalf("Failed to initialize node for enrollment: %v", err)
			}

			err = node.Enroll(context.Background(), jwtStr)
			if err != nil {
				logger.Fatalf("Enrollment failed: %v", err)
			}

			fmt.Println("Successfully joined the Sovereign Agent Mesh!")
		},
	}

	// Configure Flags
	runCmd.Flags().StringSliceVar(&listenAddrs, "listen", []string{"/ip4/0.0.0.0/udp/5001/quic-v1", "/ip4/0.0.0.0/tcp/5002"}, "libp2p Listen Addrs")
	runCmd.Flags().StringVar(&jwtFlag, "jwt", "", "Pre-fetched JWT token")
	runCmd.Flags().StringVar(&jwtPathFlag, "jwt-path", "", "Path to file containing JWT token")
	runCmd.Flags().StringVar(&clientIDFlag, "client-id", os.Getenv("SAM_OIDC_ID"), "OIDC Client ID for M2M")
	runCmd.Flags().StringVar(&clientSecretFlag, "client-secret", os.Getenv("SAM_OIDC_SECRET"), "OIDC Client Secret for M2M")
	runCmd.Flags().StringVar(&hubPublicKeyFlag, "hub-public-key", "", "Hub Public Key (32-byte Hex)")
	runCmd.Flags().StringVar(&bindAddrFlag, "bind-addr", "127.0.0.1:8080", "Local TCP address for the HTTP server (MCP and Sidecar API)")
	runCmd.Flags().StringVar(&meshFlag, "mesh", DefaultMeshName, "Mesh federation name")
	runCmd.Flags().StringVar(&discoveryIntervalFlag, "discovery-interval", DefaultDiscoveryInterval, "Polling interval for DHT discovery")
	runCmd.Flags().BoolVar(&enableRelayFlag, "enable-relay", false, "Allow this node to serve as a relay for others")
	runCmd.Flags().StringVar(&logLevelFlag, "log-level", "info", "Log level (debug, info, warn, error)")
	runCmd.Flags().DurationVar(&keyGracePeriodFlag, "key-grace-period", 24*time.Hour, "Key grace period for old keys (e.g. 24h)")
	runCmd.Flags().BoolVar(&allowLoopbackFlag, "allow-loopback", false, "Allow publishing and connecting to loopback/link-local addresses")
	joinCmd.Flags().BoolVar(&allowLoopbackFlag, "allow-loopback", false, "Allow publishing and connecting to loopback/link-local addresses")
	runCmd.Flags().StringVar(&apiTokenFlag, "api-token", "", "Static Bearer token for API authorization")
	runCmd.Flags().StringVar(&tlsCertFlag, "tls-cert", "", "Path to TLS certificate for sidecar API")
	runCmd.Flags().StringVar(&tlsKeyFlag, "tls-key", "", "Path to TLS key for sidecar API")
	runCmd.Flags().StringVar(&tlsCAFlag, "tls-ca", "", "Path to TLS CA for sidecar API mTLS")
	rootCmd.PersistentFlags().StringVar(&hubAddr, "hub", DefaultHubURL, "Hub URL")
	rootCmd.PersistentFlags().StringVar(&configFile, "config", DefaultConfigFile, "Path to sam-node.yaml configuration file")
	rootCmd.PersistentFlags().StringVar(&oidcIssuerFlag, "oidc-issuer", "", "OIDC Issuer URL")
	rootCmd.PersistentFlags().StringVar(&deviceAuthURLFlag, "device-auth-url", "", "OIDC Device Authorization URL")
	rootCmd.PersistentFlags().StringVar(&audienceFlag, "audience", api.DefaultAudience, "OIDC Audience")
	rootCmd.PersistentFlags().StringVar(&dataDirFlag, "data-dir", os.Getenv("SAM_DATA_DIR"), "Override directory for the agent store (defaults to OS user config dir)")

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(joinCmd)

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

// resolveDataDir honors --data-dir / $SAM_DATA_DIR if set, else falls back to GetDataDir().
func resolveDataDir() string {
	if dataDirFlag != "" {
		if err := os.MkdirAll(dataDirFlag, 0700); err != nil {
			logger.Fatalf("Failed to create data directory: %v", err)
		}
		return dataDirFlag
	}

	dir, err := GetDefaultDataDir()
	if err != nil {
		logger.Fatalf("Failed to get data dir: %v", err)
	}
	return dir
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
	req := &api.EnrollRequest{
		Jwt:    jwt,
		PeerId: n.Host.ID().String(),
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal enroll request: %v", err)
	}

	if !strings.HasPrefix(hubAddr, "http://") && !strings.HasPrefix(hubAddr, "https://") {
		return fmt.Errorf("hub address must be an HTTP or HTTPS URL for enrollment: %s", hubAddr)
	}
	url := hubAddr + "/register"
	logger.Infof("Enrolling via HTTP at %s", url)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Errorf("failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enrollment failed with status %s: %s", resp.Status, string(body))
	}

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	var enrollResp api.EnrollResponse
	if err := proto.Unmarshal(respData, &enrollResp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if enrollResp.ErrorMessage != "" {
		return fmt.Errorf("enrollment failed: %s", enrollResp.ErrorMessage)
	}

	if len(enrollResp.BiscuitToken) == 0 {
		return fmt.Errorf("received empty biscuit token")
	}

	if err := n.Store.SaveIdentity(enrollResp.BiscuitToken); err != nil {
		return fmt.Errorf("failed to save identity: %v", err)
	}

	if err := n.Store.SaveIdentityExpiration(enrollResp.Expiration); err != nil {
		return fmt.Errorf("failed to save identity expiration: %v", err)
	}

	if err := n.Store.SaveHubConfig(enrollResp.HubPublicKey, enrollResp.HubAddresses); err != nil {
		return fmt.Errorf("failed to save hub config: %v", err)
	}

	n.keysMu.Lock()
	n.trustedKeys = append(n.trustedKeys, TrustedKey{Key: ed25519.PublicKey(enrollResp.HubPublicKey), ReceivedAt: time.Now()})
	n.keysMu.Unlock()

	// Add known peers from response
	n.mu.Lock()
	for _, p := range enrollResp.KnownPeers {
		if n.Host != nil && p == n.Host.ID().String() {
			continue
		}
		n.knownPeers[p] = true
		fmt.Printf("[Enroll] Added known peer from hub: %s\n", p)
	}
	n.mu.Unlock()

	// Connect and Auth to hub after enrollment to join the mesh
	for _, addrStr := range enrollResp.HubAddresses {
		addr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			logger.Warnf("Failed to parse hub address from response: %v", err)
			continue
		}
		if err := n.ConnectAndAuthWithHub(ctx, addr); err != nil {
			logger.Warnf("Failed to connect and auth with hub after enrollment: %v", err)
		} else {
			break
		}
	}

	fmt.Println("Successfully enrolled via HTTP and stored identity and hub config.")
	return nil
}
