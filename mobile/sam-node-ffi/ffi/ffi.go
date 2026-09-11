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

package ffi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/node"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	activeNode  *node.SamNode
	activeStore *node.Store
	cancelFunc  context.CancelFunc
	sidecarSrv  *http.Server
	unauthSrv   *http.Server
	mu          sync.Mutex

	logger = golog.Logger("sam-node-ffi")
)

// MobileConfig holds simple configuration options for the mobile agent.
type MobileConfig struct {
	DataDir           string `json:"dataDir"`
	ControlPlaneURL   string `json:"controlPlaneURL"`
	MeshID            string `json:"meshID"`
	BindAddr          string `json:"bindAddr"`
	ApiToken          string `json:"apiToken"`
	LogLevel          string `json:"logLevel"`
	DiscoveryInterval string `json:"discoveryInterval"`
	ListenAddrs       string `json:"listenAddrs"` // comma-separated
	// Labels mirror the config file's labels map. They are attested only at
	// enrollment; a start re-announces them and re-enrollment re-sends them.
	Labels        map[string]string `json:"labels"`
	AllowLoopback bool              `json:"allowLoopback"`
	EnableRelay   bool              `json:"enableRelay"`
	// Services this node exposes, declared at start like the node config
	// file's services block; there is no runtime registration.
	Services []MobileService `json:"services,omitempty"`
	// Local attenuation, same shape as the config file's block. Go matches
	// these keys to the yaml-tagged fields case-insensitively.
	Attenuation api.Attenuation `json:"attenuation"`
}

// MobileService is one statically declared service.
type MobileService struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	TargetURL   string `json:"targetUrl"`
}

// StartNode starts the mesh node and the local sidecar API server.
func StartNode(configJSON string) error {
	mu.Lock()
	defer mu.Unlock()

	if activeNode != nil || unauthSrv != nil {
		return errors.New("node is already running")
	}

	var config MobileConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return fmt.Errorf("failed to parse config JSON: %w", err)
	}

	lvl := golog.LevelInfo
	if config.LogLevel != "" {
		if l, err := golog.LevelFromString(config.LogLevel); err == nil {
			lvl = l
		}
	}

	if config.DataDir != "" {
		_ = os.MkdirAll(config.DataDir, 0700)
		logFilePath := filepath.Join(config.DataDir, "node.log")
		golog.SetupLogging(golog.Config{
			File:   logFilePath,
			Level:  lvl,
			Stderr: false,
			Stdout: false,
		})
	} else {
		golog.SetupLogging(golog.Config{
			Level:  lvl,
			Stderr: true,
		})
	}

	store, err := node.NewStore(config.DataDir)
	if err != nil {
		return fmt.Errorf("failed to open store: %w", err)
	}
	activeStore = store

	token, _ := store.LoadIdentity()
	if len(token) == 0 {
		displayControlPlane := config.ControlPlaneURL
		if displayControlPlane == "" {
			if h, err := store.LoadControlPlaneURL(); err == nil && h != "" {
				displayControlPlane = h
			} else {
				_ = store.Close()
				activeStore = nil
				return fmt.Errorf("no control plane configured: set ControlPlaneURL to the mesh this node should join")
			}
		}
		bindAddr := config.BindAddr
		if bindAddr == "" {
			bindAddr = "127.0.0.1:8080"
		}
		srv, err := node.StartUnauthSidecarServer(displayControlPlane, bindAddr, "", "", "")
		if err != nil {
			_ = store.Close()
			activeStore = nil
			return fmt.Errorf("failed to start unauthenticated sidecar server: %w", err)
		}
		unauthSrv = srv
		return nil
	}

	var controlPlanePubKey ed25519.PublicKey
	var routerAddrs []multiaddr.Multiaddr

	// Sync config from stored/synced configuration
	storedPubKey, syncedAddrs, bannedPeerIDs, err := node.SyncMeshConfig(context.Background(), store)
	if err == nil && len(storedPubKey) > 0 {
		controlPlanePubKey = storedPubKey
		routerAddrs = syncedAddrs
	}

	priv := node.GetOrGenerateKey(store)

	var listenAddrs []string
	if config.ListenAddrs != "" {
		listenAddrs = strings.Split(config.ListenAddrs, ",")
	} else {
		// On mobile, let OS allocate random free ports
		listenAddrs = []string{"/ip4/0.0.0.0/udp/0/quic-v1", "/ip4/0.0.0.0/tcp/0"}
	}

	discoveryInterval := config.DiscoveryInterval
	if discoveryInterval == "" {
		discoveryInterval = node.DefaultDiscoveryInterval
	}

	meshID := config.MeshID
	if meshID == "" {
		meshID = node.DefaultMeshName
	}

	// Create and initialize the node
	var services []api.ServiceConfig
	for _, svc := range config.Services {
		services = append(services, api.ServiceConfig{
			Type:        svc.Type,
			Name:        svc.Name,
			Description: svc.Description,
			TargetURL:   svc.TargetURL,
		})
	}

	nodeConfig, err := node.CompleteNodeConfig(api.NodeConfig{
		Attenuation: config.Attenuation,
		Services:    services,
		Labels:      config.Labels,
	})
	if err != nil {
		_ = store.Close()
		activeStore = nil
		return err
	}

	samNode, err := node.NewSamNode(node.Options{
		PrivKey:              priv,
		ControlPlanePubKey:   controlPlanePubKey,
		RouterAddrs:          routerAddrs,
		Store:                store,
		BannedPeerIDs:        bannedPeerIDs,
		MeshID:               meshID,
		DiscoveryInterval:    discoveryInterval,
		ListenAddrs:          listenAddrs,
		EnableRelay:          config.EnableRelay,
		AllowLoopback:        config.AllowLoopback,
		NodeConfig:           nodeConfig,
		MonitorBootstrap:     2 * time.Minute,
		MonitorInterval:      1 * time.Minute,
		AutoRelayMinInterval: 30 * time.Second,
		AutoRelayBootDelay:   0 * time.Second,
		AutoRelayBackoff:     3 * time.Second,
	})
	if err != nil {
		_ = store.Close()
		activeStore = nil
		return fmt.Errorf("failed to initialize node: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancelFunc = cancel

	if err := samNode.Start(ctx); err != nil {
		cancel()
		_ = store.Close()
		activeStore = nil
		return fmt.Errorf("failed to start node: %w", err)
	}
	activeNode = samNode

	// Register the declared services, like cmd/sam-node does after Start.
	// In the background with retries: on mobile the first router connection
	// can take minutes, and RegisterStaticServices waits only briefly for
	// mesh connectivity before giving up.
	if len(services) > 0 {
		go func() {
			for {
				err := samNode.RegisterStaticServices(ctx, services)
				if err == nil {
					return
				}
				logger.Warnf("Registering static services (will retry): %v", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(3 * time.Second):
				}
			}
		}()
	}

	// Start Sidecar API Server
	bindAddr := config.BindAddr
	if bindAddr == "" {
		bindAddr = "127.0.0.1:8080"
	}
	sidecarSrv, err = node.StartSidecarServer(samNode, bindAddr, "", config.ApiToken, "", "", "")
	if err != nil {
		_ = stopNodeInternal()
		return fmt.Errorf("failed to start sidecar server: %w", err)
	}

	return nil
}

// StopNode stops the node.
func StopNode() error {
	mu.Lock()
	defer mu.Unlock()
	return stopNodeInternal()
}

func stopNodeInternal() error {
	if activeNode == nil && unauthSrv == nil {
		return errors.New("node is not running")
	}

	if sidecarSrv != nil {
		_ = sidecarSrv.Close()
		sidecarSrv = nil
	}

	if unauthSrv != nil {
		_ = unauthSrv.Close()
		unauthSrv = nil
	}

	if cancelFunc != nil {
		cancelFunc()
		cancelFunc = nil
	}

	var err error
	if activeNode != nil {
		err = activeNode.Teardown()
		activeNode = nil
	}

	if activeStore != nil {
		_ = activeStore.Close()
		activeStore = nil
	}

	return err
}

// GetNodeID returns the P2P peer ID.
func GetNodeID() string {
	mu.Lock()
	defer mu.Unlock()

	if activeNode != nil && activeNode.Host != nil {
		return activeNode.Host.ID().String()
	}
	if unauthSrv != nil {
		return "unauthenticated"
	}
	return ""
}

// decodeLabels reads the JSON object the app sends for labels; an empty
// string means none. Validation is the CLI's, so the errors match.
func decodeLabels(jsonText string) (map[string]string, error) {
	var labels map[string]string
	if jsonText != "" {
		if err := json.Unmarshal([]byte(jsonText), &labels); err != nil {
			return nil, fmt.Errorf("invalid labels: %w", err)
		}
	}
	if err := api.ValidateLabels(labels); err != nil {
		return nil, fmt.Errorf("invalid labels: %w", err)
	}
	return labels, nil
}

// EnrollNode enrolls a node. Labels arrive as a JSON object and are minted
// into the node's Biscuit here; changing them means enrolling again, which
// reuses the stored key so the PeerID survives.
func EnrollNode(dataDir string, controlPlaneURL string, jwt string, allowLoopback bool, labels string, refreshToken string) error {
	parsedLabels, err := decodeLabels(labels)
	if err != nil {
		return err
	}

	_ = os.MkdirAll(dataDir, 0700)
	logFilePath := filepath.Join(dataDir, "node.log")
	golog.SetupLogging(golog.Config{
		File:   logFilePath,
		Level:  golog.LevelDebug,
		Stderr: false,
		Stdout: false,
	})

	store, err := node.NewStore(dataDir)
	if err != nil {
		return fmt.Errorf("failed to open store: %w", err)
	}
	defer func() { _ = store.Close() }()

	priv := node.GetOrGenerateKey(store)

	var initRouterAddrs []multiaddr.Multiaddr
	if !strings.HasPrefix(controlPlaneURL, "http://") && !strings.HasPrefix(controlPlaneURL, "https://") {
		ma, err := multiaddr.NewMultiaddr(controlPlaneURL)
		if err == nil {
			initRouterAddrs = []multiaddr.Multiaddr{ma}
		}
	}

	enrollCtx, enrollCancel := context.WithCancel(context.Background())
	defer enrollCancel()

	var listenAddrs []string
	if allowLoopback {
		listenAddrs = []string{"/ip4/127.0.0.1/udp/0/quic-v1", "/ip4/127.0.0.1/tcp/0"}
	} else {
		listenAddrs = []string{"/ip4/0.0.0.0/udp/0/quic-v1", "/ip4/0.0.0.0/tcp/0"}
	}

	meshNode, err := node.NewSamNode(node.Options{
		PrivKey:       priv,
		RouterAddrs:   initRouterAddrs,
		Store:         store,
		AllowLoopback: allowLoopback,
		ListenAddrs:   listenAddrs,
		NodeConfig:    &node.NodeConfigComplete{Labels: parsedLabels},
	})
	if err != nil {
		return fmt.Errorf("failed to create node for enrollment: %w", err)
	}

	if err := meshNode.Start(enrollCtx); err != nil {
		return fmt.Errorf("failed to start node for enrollment: %w", err)
	}
	defer func() {
		_ = meshNode.Teardown()
	}()

	err = meshNode.Enroll(enrollCtx, controlPlaneURL, jwt)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	if err := store.SaveControlPlaneURL(controlPlaneURL); err != nil {
		return fmt.Errorf("failed to save control plane URL: %w", err)
	}
	if refreshToken != "" {
		saveRefreshSession(enrollCtx, store, controlPlaneURL, refreshToken)
	}

	_, _, _, err = node.SyncMeshConfig(enrollCtx, store)
	if err != nil {
		return fmt.Errorf("failed to sync mesh config post-enrollment: %w", err)
	}

	return nil
}

// FetchControlPlaneInfoJSON fetches control plane info and returns it as a JSON string.
// If an error occurs, it returns a JSON object with an "error" field.
func FetchControlPlaneInfoJSON(controlPlaneURL string) string {
	info, err := node.FetchControlPlaneInfo(context.Background(), controlPlaneURL)
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err.Error())
	}
	jsonBytes, err := protojson.Marshal(info)
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err.Error())
	}
	return string(jsonBytes)
}

// IsEnrolled checks if the node is enrolled (has a valid identity).
func IsEnrolled(dataDir string) byte {
	mu.Lock()
	running := activeNode != nil
	mu.Unlock()
	if running {
		return 1 // Running node implies enrolled
	}
	store, err := node.NewStore(dataDir)
	if err != nil {
		return 0
	}
	defer func() { _ = store.Close() }()
	token, _ := store.LoadIdentity()
	if len(token) > 0 {
		return 1
	}
	return 0
}

// GetMeshInfo returns mesh information as a JSON string.
func GetMeshInfo() string {
	mu.Lock()
	defer mu.Unlock()

	if activeNode == nil {
		return `{"error": "node not running"}`
	}
	if activeNode.Host == nil {
		return `{"error": "host not initialized"}`
	}

	peers := activeNode.Host.Network().Peers()
	dhtSize := 0
	if activeNode.DHT != nil && activeNode.DHT.RoutingTable() != nil {
		dhtSize = activeNode.DHT.RoutingTable().Size()
	}

	resData := map[string]any{
		"connected_peers": len(peers),
		"dht_size":        dhtSize,
		"node_id":         activeNode.Host.ID().String(),
	}

	jsonBytes, err := json.Marshal(resData)
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err.Error())
	}
	return string(jsonBytes)
}

// CallRemoteTool calls an MCP tool on a remote peer and returns the result as a JSON string.
func CallRemoteTool(peerIDStr string, toolName string, argsJSON string) string {
	mu.Lock()
	n := activeNode
	mu.Unlock()

	if n == nil {
		return `{"error": "node not running"}`
	}
	if n.Host == nil {
		return `{"error": "host not initialized"}`
	}

	targetPeer, err := peer.Decode(peerIDStr)
	if err != nil {
		return fmt.Sprintf(`{"error": "invalid peer ID: %s"}`, err.Error())
	}

	var params any
	if argsJSON != "" && argsJSON != "{}" {
		if err := json.Unmarshal([]byte(argsJSON), &params); err != nil {
			return fmt.Sprintf(`{"error": "invalid arguments JSON: %s"}`, err.Error())
		}
	}

	res, err := n.CallMCPTool(context.Background(), targetPeer, toolName, params, nil)
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to call tool: %s"}`, err.Error())
	}

	jsonBytes, err := json.Marshal(res)
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to marshal result: %s"}`, err.Error())
	}

	return string(jsonBytes)
}

// saveRefreshSession stores what ReEnrollNode needs to buy a JWT later.
// Failures only cost the silent path, so they are logged, not returned.
func saveRefreshSession(ctx context.Context, store *node.Store, controlPlaneURL, refreshToken string) {
	if err := store.SaveRefreshToken(refreshToken); err != nil {
		logger.Warnf("Failed to save refresh token: %v", err)
		return
	}
	info, err := node.FetchControlPlaneInfo(ctx, controlPlaneURL)
	if err != nil {
		logger.Warnf("Failed to fetch control plane info for OIDC config: %v", err)
		return
	}
	if err := store.SaveOIDCConfig(info.OidcIssuer, info.ClientId, info.Audience); err != nil {
		logger.Warnf("Failed to save OIDC config: %v", err)
	}
}

// ReEnrollNode re-attests labels without a browser: the refresh token saved
// at enrollment buys a JWT and the stored key keeps the PeerID. Fails when
// no token was saved or it expired; the app then falls back to the browser.
func ReEnrollNode(dataDir string, labels string) error {
	mu.Lock()
	defer mu.Unlock()
	if activeNode != nil || unauthSrv != nil {
		return errors.New("stop the node before re-enrolling")
	}
	parsedLabels, err := decodeLabels(labels)
	if err != nil {
		return err
	}
	store, err := node.NewStore(dataDir)
	if err != nil {
		return fmt.Errorf("failed to open store: %w", err)
	}
	defer func() { _ = store.Close() }()

	meshNode, err := node.NewSamNode(node.Options{
		PrivKey:       node.GetOrGenerateKey(store),
		Store:         store,
		AllowLoopback: true,
		ListenAddrs:   []string{"/ip4/127.0.0.1/tcp/0"},
		NodeConfig:    &node.NodeConfigComplete{Labels: parsedLabels},
	})
	if err != nil {
		return fmt.Errorf("failed to create node for re-enrollment: %w", err)
	}
	if err := meshNode.ReEnrollWithRefreshToken(context.Background()); err != nil {
		return fmt.Errorf("re-enrollment failed: %w", err)
	}
	return nil
}
