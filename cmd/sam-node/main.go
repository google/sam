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
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/node"
	golog "github.com/ipfs/go-log/v2"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	"github.com/spf13/cobra"
)

func init() {
	if dnsServer := os.Getenv("SAM_TEST_DNS_SERVER"); dnsServer != "" {
		customResolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", dnsServer)
			},
		}
		net.DefaultResolver = customResolver
		madns.DefaultResolver, _ = madns.NewResolver(madns.WithDefaultResolver(customResolver))
	}
}

var (
	hubAddr                  string
	jwtFlag                  string
	jwtPathFlag              string
	bootstrapTokenFlag       string
	clientIDFlag             string
	clientSecretFlag         string
	hubPublicKeyFlag         string
	bindAddrFlag             string
	meshFlag                 string
	discoveryIntervalFlag    string
	listenAddrs              []string
	enableRelayFlag          bool
	configFile               string
	oidcIssuerFlag           string
	deviceAuthURLFlag        string
	audienceFlag             string
	dataDirFlag              string
	headlessFlag             bool
	offlineAccessFlag        bool
	logLevelFlag             string
	keyGracePeriodFlag       time.Duration
	allowLoopbackFlag        bool
	monitorBootstrapFlag     time.Duration
	monitorCheckIntervalFlag time.Duration
	autoRelayMinIntervalFlag time.Duration
	autoRelayBootDelayFlag   time.Duration
	autoRelayBackoffFlag     time.Duration
	hubConnectTimeoutFlag    time.Duration
	apiTokenFlag             string
	tlsCertFlag              string
	tlsKeyFlag               string
	tlsCAFlag                string
)

var logger = golog.Logger("sam-node-cli")

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
			// Configure logging to duplicate to ring buffer
			cfg := golog.GetConfig()
			cfg.URL = "ringbuffer://"
			golog.SetupLogging(cfg)

			// Initialize logging
			golog.SetAllLoggers(golog.LevelInfo)
			if logLevelFlag != "" {
				lvl, err := golog.LevelFromString(logLevelFlag)
				if err == nil {
					golog.SetAllLoggers(lvl)
				}
			}

			// Suppress noisy DHT logs
			_ = golog.SetLogLevel("dht", "fatal")
			_ = golog.SetLogLevel("dht/RtRefreshManager", "fatal")

			store, err := node.NewStore(resolveDataDir())
			if err != nil {
				logger.Fatalf("Failed to open store: %v", err)
			}

			nodeConfig, err := node.LoadNodeConfig(configFile)
			if err != nil {
				logger.Fatalf("Failed to load node config: %v", err)
			}
			defer func() {
				if err := store.Close(); err != nil {
					logger.Errorf("closing store: %v", err)
				}
			}()

			var hubPubKey ed25519.PublicKey
			var hubAddrs []multiaddr.Multiaddr

			storedPubKey, syncedAddrs, err := node.SyncHubConfig(context.Background(), store)
			if err != nil {
				logger.Warnf("Failed to sync hub config: %v", err)
			}
			if len(storedPubKey) > 0 {
				hubPubKey = storedPubKey
				hubAddrs = syncedAddrs
			}

			if hubPublicKeyFlag != "" {
				pubBytes, err := hex.DecodeString(strings.TrimSpace(hubPublicKeyFlag))
				if err != nil {
					logger.Fatalf("Invalid hub public key: %v", err)
				}
				hubPubKey = pubBytes
			}

			var meshNode *node.SamNode

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
				dummyNode := &node.SamNode{}
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

			if jwtStr == "" && bootstrapTokenFlag == "" {
				token, _ := store.LoadIdentity()
				if len(token) == 0 {
					displayHub := hubAddr
					if displayHub == "" {
						if h, err := store.LoadHubURL(); err == nil && h != "" {
							displayHub = h
						} else {
							displayHub = "https://bananas.sam-mesh.dev"
						}
					}
					logger.Infof("No identity found. Starting unauthenticated sidecar for enrollment over MCP...")
					unauthSrv, err := node.StartUnauthSidecarServer(displayHub, bindAddrFlag, tlsCertFlag, tlsKeyFlag)
					if err != nil {
						logger.Fatalf("Failed to start unauthenticated sidecar: %v", err)
					}
					defer func() {
						_ = unauthSrv.Close()
					}()
					<-ctx.Done()
					return
				}
				logger.Infoln("Using stored identity.")

				if len(hubPubKey) == 0 {
					logger.Fatal("Hub public key not found in store and not provided. Cannot verify peers.")
				}
				priv := node.GetOrGenerateKey(store)
				meshNode, err = node.NewSamNode(node.Options{
					PrivKey:              priv,
					HubPubKey:            hubPubKey,
					HubAddrs:             hubAddrs,
					Store:                store,
					MeshID:               meshFlag,
					DiscoveryInterval:    discoveryIntervalFlag,
					ListenAddrs:          listenAddrs,
					EnableRelay:          enableRelayFlag,
					NodeConfig:           nodeConfig,
					KeyGracePeriod:       keyGracePeriodFlag,
					AllowLoopback:        allowLoopbackFlag,
					MonitorBootstrap:     monitorBootstrapFlag,
					MonitorInterval:      monitorCheckIntervalFlag,
					AutoRelayMinInterval: autoRelayMinIntervalFlag,
					AutoRelayBootDelay:   autoRelayBootDelayFlag,
					AutoRelayBackoff:     autoRelayBackoffFlag,
					HubConnectTimeout:    hubConnectTimeoutFlag,
				})
				if err != nil {
					logger.Fatalf("Failed to initialize mesh node: %v", err)
				}
				if err := meshNode.Start(ctx); err != nil {
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

				priv := node.GetOrGenerateKey(store)
				enrollCtx, enrollCancel := context.WithCancel(context.Background())
				meshNode, err = node.NewSamNode(node.Options{
					PrivKey:              priv,
					HubAddrs:             initHubAddrs,
					Store:                store,
					MeshID:               meshFlag,
					DiscoveryInterval:    discoveryIntervalFlag,
					ListenAddrs:          listenAddrs,
					EnableRelay:          enableRelayFlag,
					NodeConfig:           nodeConfig,
					KeyGracePeriod:       keyGracePeriodFlag,
					AllowLoopback:        allowLoopbackFlag,
					MonitorBootstrap:     monitorBootstrapFlag,
					MonitorInterval:      monitorCheckIntervalFlag,
					AutoRelayMinInterval: autoRelayMinIntervalFlag,
					AutoRelayBootDelay:   autoRelayBootDelayFlag,
					AutoRelayBackoff:     autoRelayBackoffFlag,
					HubConnectTimeout:    hubConnectTimeoutFlag,
				})
				if err != nil {
					enrollCancel()
					logger.Fatalf("Failed to initialize node for enrollment: %v", err)
				}
				if err := meshNode.Start(enrollCtx); err != nil {
					enrollCancel()
					logger.Fatalf("Failed to start node for enrollment: %v", err)
				}

				if bootstrapTokenFlag != "" {
					err = meshNode.EnrollBootstrap(enrollCtx, hubAddr, bootstrapTokenFlag)
				} else {
					err = meshNode.Enroll(enrollCtx, hubAddr, jwtStr)
				}
				if err != nil {
					if teardownErr := meshNode.Teardown(); teardownErr != nil {
						logger.Errorf("Teardown failed during enrollment error cleanup: %v", teardownErr)
					}
					enrollCancel()
					logger.Fatalf("Enrollment failed: %v", err)
				}
				if err := store.SaveHubURL(hubAddr); err != nil {
					logger.Warnf("Failed to save hub URL: %v", err)
				}

				if teardownErr := meshNode.Teardown(); teardownErr != nil {
					logger.Errorf("Failed to teardown enrollment node: %v", teardownErr)
				}
				enrollCancel()

				storedPubKey, newHubAddrs, err := node.SyncHubConfig(context.Background(), store)
				if err != nil {
					logger.Warnf("Failed to sync hub config post-enrollment: %v", err)
				}
				hubPubKey = storedPubKey

				logger.Debugf("listenAddrs: %v, allowLoopback: %v", listenAddrs, allowLoopbackFlag)
				meshNode, err = node.NewSamNode(node.Options{
					PrivKey:              priv,
					HubPubKey:            hubPubKey,
					HubAddrs:             newHubAddrs,
					Store:                store,
					MeshID:               meshFlag,
					DiscoveryInterval:    discoveryIntervalFlag,
					ListenAddrs:          listenAddrs,
					EnableRelay:          enableRelayFlag,
					NodeConfig:           nodeConfig,
					KeyGracePeriod:       keyGracePeriodFlag,
					AllowLoopback:        allowLoopbackFlag,
					MonitorBootstrap:     monitorBootstrapFlag,
					MonitorInterval:      monitorCheckIntervalFlag,
					AutoRelayMinInterval: autoRelayMinIntervalFlag,
					AutoRelayBootDelay:   autoRelayBootDelayFlag,
					AutoRelayBackoff:     autoRelayBackoffFlag,
					HubConnectTimeout:    hubConnectTimeoutFlag,
				})
				if err != nil {
					logger.Fatalf("Failed to initialize node after enrollment: %v", err)
				}
				if err := meshNode.Start(ctx); err != nil {
					logger.Fatalf("Failed to start node after enrollment: %v", err)
				}
			}

			// Register static services from config
			if nodeConfig != nil && len(nodeConfig.Services) > 0 {
				if err := meshNode.RegisterStaticServices(context.Background(), nodeConfig.Services); err != nil {
					logger.Fatalf("Failed to register static services: %v", err)
				}
			}

			// Start renewal loop
			meshNode.StartRenewalLoop(ctx, oidcIssuerFlag, clientIDFlag, clientSecretFlag, jwtPathFlag)

			meshNode.Host.SetStreamHandler(api.AuthProtocolID, meshNode.HandleAuthHandshake)

			// Start Sidecar API Server (multiplexed with MCP)
			sidecarSrv, err := node.StartSidecarServer(meshNode, bindAddrFlag, apiTokenFlag, tlsCertFlag, tlsKeyFlag, tlsCAFlag)
			if err != nil {
				logger.Fatalf("Failed to start sidecar server: %v", err)
			}
			defer func() {
				_ = sidecarSrv.Close()
			}()

			fmt.Printf("SAM Node Online.\nPeerID: %s\nListening on: %v\n", meshNode.Host.ID(), meshNode.Host.Addrs())

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

			store, err := node.NewStore(resolveDataDir())
			if err != nil {
				logger.Fatalf("Failed to open store: %v", err)
			}

			nodeConfig, err := node.LoadNodeConfig(configFile)
			if err != nil {
				logger.Fatalf("Failed to load node config: %v", err)
			}
			defer func() {
				if err := store.Close(); err != nil {
					logger.Errorf("closing store: %v", err)
				}
			}()

			dummyNode := &node.SamNode{Store: store}

			fmt.Printf("Discovering hub info from %s...\n", targetHub)
			hubInfo, err := node.FetchHubInfo(ctx, targetHub)
			if err != nil {
				logger.Fatalf("Failed to discover hub info: %v", err)
			}

			var jwtStr string
			if bootstrapTokenFlag == "" {
				fmt.Printf("OIDC Issuer discovered: %s\n", hubInfo.OidcIssuer)
				fmt.Printf("Client ID discovered: %s\n", hubInfo.ClientId)

				logger.Info("Discovering OIDC endpoints...")
				tokenURL, authURL, err := dummyNode.DiscoverEndpoints(ctx, hubInfo.OidcIssuer)
				if err != nil {
					logger.Fatalf("Failed to discover OIDC endpoints: %v", err)
				}

				jwtStr, err = dummyNode.InteractiveLogin(ctx, authURL, tokenURL, hubInfo.ClientId, hubInfo.Audience, offlineAccessFlag, headlessFlag)
				if err != nil {
					logger.Fatalf("Failed to get token: %v", err)
				}
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

			priv := node.GetOrGenerateKey(store)
			meshNode, err := node.NewSamNode(node.Options{
				PrivKey:              priv,
				HubAddrs:             initHubAddrs,
				Store:                store,
				MeshID:               meshFlag,
				DiscoveryInterval:    discoveryIntervalFlag,
				ListenAddrs:          []string{"/ip4/0.0.0.0/udp/0/quic-v1", "/ip4/0.0.0.0/tcp/0"},
				EnableRelay:          enableRelayFlag,
				NodeConfig:           nodeConfig,
				KeyGracePeriod:       keyGracePeriodFlag,
				AllowLoopback:        allowLoopbackFlag,
				MonitorBootstrap:     2 * time.Minute,
				MonitorInterval:      1 * time.Minute,
				AutoRelayMinInterval: 30 * time.Second,
				AutoRelayBootDelay:   0 * time.Second,
				AutoRelayBackoff:     3 * time.Second,
				HubConnectTimeout:    hubConnectTimeoutFlag,
			})
			if err != nil {
				logger.Fatalf("Failed to initialize node for enrollment: %v", err)
			}
			if err := meshNode.Start(ctx); err != nil {
				logger.Fatalf("Failed to start node for enrollment: %v", err)
			}

			if bootstrapTokenFlag != "" {
				err = meshNode.EnrollBootstrap(ctx, targetHub, bootstrapTokenFlag)
			} else {
				err = meshNode.Enroll(ctx, targetHub, jwtStr)
			}
			if err != nil {
				logger.Fatalf("Enrollment failed: %v", err)
			}
			if err := store.SaveHubURL(targetHub); err != nil {
				logger.Warnf("Failed to save hub URL: %v", err)
			}
			if bootstrapTokenFlag == "" {
				if err := store.SaveOIDCConfig(hubInfo.OidcIssuer, hubInfo.ClientId, hubInfo.Audience); err != nil {
					logger.Warnf("Failed to save OIDC config: %v", err)
				}
			}

			fmt.Println("Successfully joined the Sovereign Agent Mesh!")
		},
	}

	// Configure Flags
	runCmd.Flags().StringSliceVar(&listenAddrs, "listen", []string{"/ip4/0.0.0.0/udp/5001/quic-v1", "/ip4/0.0.0.0/tcp/5002"}, "libp2p Listen Addrs")
	runCmd.Flags().StringVar(&jwtFlag, "jwt", "", "Pre-fetched JWT token")
	runCmd.Flags().StringVar(&jwtPathFlag, "jwt-path", "", "Path to file containing JWT token")
	runCmd.Flags().StringVar(&bootstrapTokenFlag, "bootstrap-token", "", "Pre-shared bootstrap token for enrollment")
	runCmd.Flags().StringVar(&clientIDFlag, "client-id", "", "OIDC Client ID for M2M")
	runCmd.Flags().StringVar(&clientSecretFlag, "client-secret", "", "OIDC Client Secret for M2M")
	runCmd.Flags().StringVar(&hubPublicKeyFlag, "hub-public-key", "", "Hub Public Key (32-byte Hex)")
	runCmd.Flags().StringVar(&bindAddrFlag, "bind-addr", "127.0.0.1:8080", "Local TCP address for the HTTP server (MCP and Sidecar API)")
	runCmd.Flags().StringVar(&meshFlag, "mesh", node.DefaultMeshName, "Mesh federation name")
	runCmd.Flags().StringVar(&discoveryIntervalFlag, "discovery-interval", node.DefaultDiscoveryInterval, "Polling interval for DHT discovery")
	runCmd.Flags().DurationVar(&monitorBootstrapFlag, "monitor-bootstrap", 2*time.Minute, "Initial wait before monitoring hub connection")
	runCmd.Flags().DurationVar(&monitorCheckIntervalFlag, "monitor-interval", 1*time.Minute, "Interval for checking hub connection")
	runCmd.Flags().DurationVar(&autoRelayMinIntervalFlag, "autorelay-min-interval", 30*time.Second, "AutoRelay Min Interval")
	runCmd.Flags().DurationVar(&autoRelayBootDelayFlag, "autorelay-boot-delay", 0*time.Second, "AutoRelay Boot Delay")
	runCmd.Flags().DurationVar(&autoRelayBackoffFlag, "autorelay-backoff", 3*time.Second, "AutoRelay Backoff")
	runCmd.Flags().DurationVar(&hubConnectTimeoutFlag, "hub-connect-timeout", node.DefaultHubConnectTimeout, "Timeout for dialing each hub address")
	runCmd.Flags().BoolVar(&enableRelayFlag, "enable-relay", false, "Allow this node to serve as a relay for others")
	runCmd.Flags().StringVar(&logLevelFlag, "log-level", "info", "Log level (debug, info, warn, error)")
	runCmd.Flags().DurationVar(&keyGracePeriodFlag, "key-grace-period", 24*time.Hour, "Key grace period for old keys (e.g. 24h)")
	runCmd.Flags().BoolVar(&allowLoopbackFlag, "allow-loopback", false, "Allow publishing and connecting to loopback/link-local addresses")
	joinCmd.Flags().BoolVar(&allowLoopbackFlag, "allow-loopback", false, "Allow publishing and connecting to loopback/link-local addresses")
	joinCmd.Flags().DurationVar(&hubConnectTimeoutFlag, "hub-connect-timeout", node.DefaultHubConnectTimeout, "Timeout for dialing each hub address")
	joinCmd.Flags().BoolVar(&offlineAccessFlag, "offline-access", false, "Request OIDC offline access/refresh token for automatic renewal")
	joinCmd.Flags().StringVar(&bootstrapTokenFlag, "bootstrap-token", "", "Pre-shared bootstrap token for enrollment")
	runCmd.Flags().StringVar(&apiTokenFlag, "api-token", "", "Static Bearer token for API authorization")
	runCmd.Flags().StringVar(&tlsCertFlag, "tls-cert", "", "Path to TLS certificate for sidecar API")
	runCmd.Flags().StringVar(&tlsKeyFlag, "tls-key", "", "Path to TLS key for sidecar API")
	runCmd.Flags().StringVar(&tlsCAFlag, "tls-ca", "", "Path to TLS CA for sidecar API mTLS")
	rootCmd.PersistentFlags().StringVar(&hubAddr, "hub", "", "Hub URL")
	rootCmd.PersistentFlags().StringVar(&configFile, "config", node.DefaultConfigFile, "Path to sam-node.yaml configuration file")
	rootCmd.PersistentFlags().StringVar(&oidcIssuerFlag, "oidc-issuer", "", "OIDC Issuer URL")
	rootCmd.PersistentFlags().StringVar(&deviceAuthURLFlag, "device-auth-url", "", "OIDC Device Authorization URL")
	rootCmd.PersistentFlags().StringVar(&audienceFlag, "audience", api.DefaultAudience, "OIDC Audience")
	rootCmd.PersistentFlags().StringVar(&dataDirFlag, "data-dir", "", "Override directory for the agent store (defaults to OS user config dir)")
	rootCmd.PersistentFlags().BoolVar(&headlessFlag, "headless", false, "Force headless out-of-band (OOB) authentication flow")

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
		signal.Stop(sigChan)
	}()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

// resolveDataDir honors --data-dir / $SAM_DATA_DIR if set, else falls back to GetDefaultDataDir().
func resolveDataDir() string {
	var dir string
	if dataDirFlag != "" {
		dir = dataDirFlag
	} else {
		d, err := node.GetDefaultDataDir()
		if err != nil {
			logger.Fatalf("Failed to get default data directory: %v", err)
		}
		dir = d
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		logger.Fatalf("Failed to create data directory: %v", err)
	}
	return dir
}
