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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/hub"
	golog "github.com/ipfs/go-log/v2"
	madns "github.com/multiformats/go-multiaddr-dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	oidcIssuer            string
	clientID              string
	biscuitHex            string
	listenAddrs           []string
	meshName              string
	insecureSkipTLSVerify bool
	logLevel              string
	policyFile            string
	keyRotationInterval   time.Duration
	keyGracePeriod        time.Duration
	keysDBPath            string
	bindAddress           string
	adminToken            string
	tlsCertFile           string
	tlsKeyFile            string
	tlsCAFile             string
	externalMultiaddrs    []string
	allowedAudiencesFlag  string
	allowLoopbackFlag     bool
)

var logger = golog.Logger("sam-hub-cli")

func main() {
	rootCmd := &cobra.Command{
		Use:   "sam-hub",
		Short: "Sovereign Agent Mesh - Multi-Transport Hub",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
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
			// Suppress noisy DHT logs
			_ = golog.SetLogLevel("dht", "fatal")
			_ = golog.SetLogLevel("dht/RtRefreshManager", "fatal")

			policyConfig, err := hub.LoadPolicyConfig(policyFile)
			if err != nil {
				logger.Fatal(err)
			}

			var serverTlsConfig *tls.Config
			if tlsCertFile != "" && tlsKeyFile != "" {
				cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
				if err != nil {
					logger.Fatalf("Failed to load TLS cert: %v", err)
				}
				serverTlsConfig = &tls.Config{
					Certificates: []tls.Certificate{cert},
				}
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

			hOpts := hub.Options{
				OIDCIssuer:            oidcIssuer,
				ClientID:              clientID,
				BiscuitHex:            biscuitHex,
				ListenAddrs:           listenAddrs,
				MeshName:              meshName,
				InsecureSkipTLSVerify: insecureSkipTLSVerify,
				PolicyFile:            policyFile,
				KeyRotationInterval:   keyRotationInterval,
				KeyGracePeriod:        keyGracePeriod,
				KeysDBPath:            keysDBPath,
				BindAddress:           bindAddress,
				AdminToken:            adminToken,
				TLSCertFile:           tlsCertFile,
				TLSKeyFile:            tlsKeyFile,
				TLSCAFile:             tlsCAFile,
				ExternalMultiaddrs:    externalMultiaddrs,
				AllowedAudiences:      auds,
				AllowLoopback:         allowLoopbackFlag,
				Policy:                policyConfig,
			}

			h, err := hub.NewHub(hOpts)
			if err != nil {
				logger.Fatal(err)
			}
			defer func() {
				if err := h.Close(); err != nil {
					logger.Errorf("Failed to close hub: %v", err)
				}
			}()

			if err := h.Start(ctx); err != nil {
				logger.Fatalf("Failed to start hub: %v", err)
			}

			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}))
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
				if h.Ready() {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("ok"))
				} else {
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte("not ready"))
				}
			})

			mux.HandleFunc("/register", h.HandleRegisterHTTP)
			mux.HandleFunc("/info", h.HandleInfoHTTP)
			mux.HandleFunc("/admin/ban", func(w http.ResponseWriter, r *http.Request) {
				if adminToken != "" {
					authHeader := r.Header.Get("Authorization")
					if authHeader != "Bearer "+adminToken {
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}
				}
				hub.HandleBan(h)(w, r)
			})

			server := &http.Server{
				Addr:              bindAddress,
				Handler:           mux,
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       10 * time.Second,
				WriteTimeout:      10 * time.Second,
				IdleTimeout:       120 * time.Second,
			}

			go func() {
				if serverTlsConfig != nil {
					server.TLSConfig = serverTlsConfig
					if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
						logger.Fatalf("HTTP server failed: %v", err)
					}
				} else {
					if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						logger.Fatalf("HTTP server failed: %v", err)
					}
				}
			}()

			logger.Infof("SAM Hub Online (HTTP on %s, P2P on %v)", bindAddress, listenAddrs)
			h.SetReady(true)
			logger.Infof("MeshID: %s", h.MeshID)
			logger.Infof("PeerID: %s", h.Host.ID())
			<-ctx.Done()

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		},
	}

	defIssuer := os.Getenv("SAM_OIDC_ISSUER")
	if defIssuer == "" {
		defIssuer = hub.DefaultOIDCIssuer
	}
	rootCmd.Flags().StringVar(&oidcIssuer, "issuer", defIssuer, "OIDC Issuer URL")
	rootCmd.Flags().StringVar(&clientID, "client-id", os.Getenv("SAM_OIDC_ID"), "OIDC Client ID")
	rootCmd.Flags().StringVar(&biscuitHex, "key", os.Getenv("SAM_HUB_KEY"), "Hub Private Key (32-byte Hex)")
	rootCmd.Flags().StringSliceVar(&listenAddrs, "listen", []string{}, "libp2p Listen Addrs")
	rootCmd.Flags().StringSliceVar(&externalMultiaddrs, "external-multiaddr", []string{}, "External multiaddrs to announce")
	rootCmd.Flags().StringVar(&meshName, "mesh", hub.DefaultMeshName, "Mesh federation name")
	rootCmd.Flags().StringVar(&allowedAudiencesFlag, "allowed-audiences", api.DefaultAudience, "Comma-separated list of allowed OIDC audiences")
	rootCmd.Flags().BoolVar(&insecureSkipTLSVerify, "insecure-skip-tls-verify", false, "Skip TLS verification for OIDC issuers")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().StringVar(&policyFile, "policy-file", hub.DefaultPolicyFile, "Path to policies.yaml")
	rootCmd.Flags().DurationVar(&keyRotationInterval, "key-rotation-interval", 0, "Key rotation interval (e.g. 12h). 0 disables rotation.")
	rootCmd.Flags().DurationVar(&keyGracePeriod, "key-grace-period", 24*time.Hour, "Key grace period for old keys (e.g. 24h).")
	rootCmd.Flags().StringVar(&keysDBPath, "keys-db", hub.DefaultKeysDBPath, "Path to BoltDB file for keys")
	rootCmd.PersistentFlags().StringVar(&bindAddress, "bind-address", hub.DefaultBindAddress, "Address to listen on for HTTP/HTTPS service")
	rootCmd.PersistentFlags().StringVar(&adminToken, "admin-token", "", "Secret token for authorizing admin requests")
	rootCmd.PersistentFlags().StringVar(&tlsCertFile, "tls-cert-file", "", "Path to TLS certificate for the server")
	rootCmd.PersistentFlags().StringVar(&tlsKeyFile, "tls-key-file", "", "Path to TLS private key for the server")
	rootCmd.PersistentFlags().StringVar(&tlsCAFile, "tls-ca-file", "", "Path to CA certificate to verify client certificates (enables mTLS)")
	rootCmd.Flags().BoolVar(&allowLoopbackFlag, "allow-loopback", false, "Allow publishing and connecting to loopback/link-local addresses")

	var peerToBan string
	var banReason string
	var connectAddr string

	adminCmd := &cobra.Command{
		Use:   "admin",
		Short: "Administrative commands for SAM Hub",
	}

	banCmd := &cobra.Command{
		Use:   "ban",
		Short: "Ban a peer from the mesh",
		Run: func(cmd *cobra.Command, args []string) {
			if peerToBan == "" {
				logger.Fatal("Missing --peer flag")
			}

			targetAddr := bindAddress
			if strings.HasPrefix(targetAddr, ":") {
				targetAddr = "localhost" + targetAddr
			}

			scheme := "http"
			var tlsConfig *tls.Config
			if tlsCertFile != "" || tlsCAFile != "" {
				scheme = "https"
				tlsConfig = &tls.Config{
					InsecureSkipVerify: true, // For tests, usually self-signed
				}
				if tlsCAFile != "" {
					caCert, err := os.ReadFile(tlsCAFile)
					if err != nil {
						logger.Fatalf("Failed to read CA cert: %v", err)
					}
					caCertPool := x509.NewCertPool()
					caCertPool.AppendCertsFromPEM(caCert)
					tlsConfig.RootCAs = caCertPool
					tlsConfig.InsecureSkipVerify = false // Verify if CA is provided!
				}
			}

			client := &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
			}

			url := fmt.Sprintf("%s://%s/admin/ban?peer=%s", scheme, targetAddr, peerToBan)
			req, err := http.NewRequest("POST", url, nil)
			if err != nil {
				logger.Fatalf("Failed to create request: %v", err)
			}

			if adminToken != "" {
				req.Header.Set("Authorization", "Bearer "+adminToken)
			}

			resp, err := client.Do(req)
			if err != nil {
				logger.Fatalf("Failed to send ban request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				logger.Fatalf("Ban request failed: %s", resp.Status)
			}

			fmt.Printf("Published BANNED event for peer %s\n", peerToBan)
		},
	}

	banCmd.Flags().StringVar(&peerToBan, "peer", "", "Peer ID to ban")
	banCmd.Flags().StringVar(&banReason, "reason", "", "Reason for banning")
	banCmd.Flags().StringVar(&connectAddr, "connect", "", "Address of a peer in the mesh to connect to")

	adminCmd.AddCommand(banCmd)
	rootCmd.AddCommand(adminCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
