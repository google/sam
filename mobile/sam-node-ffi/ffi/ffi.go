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

	"github.com/google/sam/internal/node"
	golog "github.com/ipfs/go-log/v2"
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
)

// MobileConfig holds simple configuration options for the mobile agent.
type MobileConfig struct {
	DataDir           string `json:"dataDir"`
	HubURL            string `json:"hubURL"`
	MeshID            string `json:"meshID"`
	BindAddr          string `json:"bindAddr"`
	ApiToken          string `json:"apiToken"`
	LogLevel          string `json:"logLevel"`
	DiscoveryInterval string `json:"discoveryInterval"`
	ListenAddrs       string `json:"listenAddrs"` // comma-separated
	AllowLoopback     bool   `json:"allowLoopback"`
	EnableRelay       bool   `json:"enableRelay"`
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
		displayHub := config.HubURL
		if displayHub == "" {
			if h, err := store.LoadHubURL(); err == nil && h != "" {
				displayHub = h
			} else {
				displayHub = "https://bananas.sam-mesh.dev"
			}
		}
		bindAddr := config.BindAddr
		if bindAddr == "" {
			bindAddr = "127.0.0.1:8080"
		}
		srv, err := node.StartUnauthSidecarServer(displayHub, bindAddr, "", "")
		if err != nil {
			_ = store.Close()
			activeStore = nil
			return fmt.Errorf("failed to start unauthenticated sidecar server: %w", err)
		}
		unauthSrv = srv
		return nil
	}

	var hubPubKey ed25519.PublicKey
	var hubAddrs []multiaddr.Multiaddr

	// Sync config from stored/synced configuration
	storedPubKey, syncedAddrs, err := node.SyncHubConfig(context.Background(), store)
	if err == nil && len(storedPubKey) > 0 {
		hubPubKey = storedPubKey
		hubAddrs = syncedAddrs
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
	samNode, err := node.NewSamNode(node.Options{
		PrivKey:              priv,
		HubPubKey:            hubPubKey,
		HubAddrs:             hubAddrs,
		Store:                store,
		MeshID:               meshID,
		DiscoveryInterval:    discoveryInterval,
		ListenAddrs:          listenAddrs,
		EnableRelay:          config.EnableRelay,
		AllowLoopback:        config.AllowLoopback,
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

	// Start Sidecar API Server
	bindAddr := config.BindAddr
	if bindAddr == "" {
		bindAddr = "127.0.0.1:8080"
	}
	sidecarSrv, err = node.StartSidecarServer(samNode, bindAddr, config.ApiToken, "", "", "")
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

// EnrollNode enrolls a node.
func EnrollNode(dataDir string, hubURL string, jwt string, allowLoopback bool) error {
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

	var initHubAddrs []multiaddr.Multiaddr
	if !strings.HasPrefix(hubURL, "http://") && !strings.HasPrefix(hubURL, "https://") {
		ma, err := multiaddr.NewMultiaddr(hubURL)
		if err == nil {
			initHubAddrs = []multiaddr.Multiaddr{ma}
		}
	}

	enrollCtx, enrollCancel := context.WithCancel(context.Background())
	defer enrollCancel()

	meshNode, err := node.NewSamNode(node.Options{
		PrivKey:       priv,
		HubAddrs:      initHubAddrs,
		Store:         store,
		AllowLoopback: allowLoopback,
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

	err = meshNode.Enroll(enrollCtx, hubURL, jwt)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	if err := store.SaveHubURL(hubURL); err != nil {
		return fmt.Errorf("failed to save hub URL: %w", err)
	}

	_, _, err = node.SyncHubConfig(enrollCtx, store)
	if err != nil {
		return fmt.Errorf("failed to sync hub config post-enrollment: %w", err)
	}

	return nil
}

// FetchHubInfoJSON fetches hub info and returns it as a JSON string.
// If an error occurs, it returns a JSON object with an "error" field.
func FetchHubInfoJSON(hubURL string) string {
	info, err := node.FetchHubInfo(context.Background(), hubURL)
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
	if activeNode != nil {
		return 1 // Running node implies enrolled
	}
	store, err := node.NewStore(dataDir)
	if err != nil {
		return 0
	}
	defer store.Close()
	token, _ := store.LoadIdentity()
	if len(token) > 0 {
		return 1
	}
	return 0
}

// GetMeshInfo returns mesh information as a JSON string.
func GetMeshInfo() string {
	if activeNode == nil {
		return `{"error": "node not running"}`
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
