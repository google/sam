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

package node

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
)

const (
	DefaultMeshName          = "public-mesh"
	DefaultDiscoveryInterval = "30s"
	DefaultConfigFile        = "sam-node.yaml"
	DefaultHubConnectTimeout = 5 * time.Second
)

// Options holds all configuration options for a SamNode.
type Options struct {
	PrivKey              crypto.PrivKey
	HubPubKey            ed25519.PublicKey
	HubAddrs             []multiaddr.Multiaddr
	Store                *Store
	MeshID               string
	DiscoveryInterval    string
	ListenAddrs          []string
	EnableRelay          bool
	NodeConfig           *NodeConfigComplete
	KeyGracePeriod       time.Duration
	AllowLoopback        bool
	MonitorBootstrap     time.Duration
	MonitorInterval      time.Duration
	AutoRelayMinInterval time.Duration
	AutoRelayBootDelay   time.Duration
	AutoRelayBackoff     time.Duration
	// HubConnectTimeout bounds each hub address's dial (connect + stream open).
	HubConnectTimeout time.Duration
	// DHT Options
	DHTProviderAddrTTL   time.Duration
	DHTMaxRecordAge      time.Duration
	DHTLookupLimit       int
	DiscoveryConcurrency int
	// RequiredRole restricts enrollment and startup to only accept tokens containing this role.
	RequiredRole string
	// PolicySyncInterval specifies how often the node syncs the mesh policy from the Hub.
	PolicySyncInterval time.Duration
}

// Default applies default values to Options if they are not specified.
func (o *Options) Default() {
	if o.MeshID == "" {
		o.MeshID = "public-mesh"
	}
	if o.DiscoveryInterval == "" {
		o.DiscoveryInterval = "30s"
	}
	if o.MonitorBootstrap == 0 {
		o.MonitorBootstrap = 2 * time.Minute
	}
	if o.MonitorInterval == 0 {
		o.MonitorInterval = 1 * time.Minute
	}
	if o.AutoRelayMinInterval == 0 {
		o.AutoRelayMinInterval = 30 * time.Second
	}
	if o.AutoRelayBackoff == 0 {
		o.AutoRelayBackoff = 3 * time.Second
	}
	if o.KeyGracePeriod == 0 {
		o.KeyGracePeriod = 24 * time.Hour
	}
	if o.HubConnectTimeout == 0 {
		o.HubConnectTimeout = DefaultHubConnectTimeout
	}
	if o.DHTLookupLimit <= 0 {
		o.DHTLookupLimit = 20
	}
	if o.DiscoveryConcurrency <= 0 {
		o.DiscoveryConcurrency = 10
	}
	if len(o.ListenAddrs) == 0 {
		o.ListenAddrs = []string{"/ip4/0.0.0.0/udp/5001/quic-v1", "/ip4/0.0.0.0/tcp/5002"}
	}
	if o.RequiredRole == "" {
		o.RequiredRole = api.RoleNode
	}
	if o.PolicySyncInterval == 0 {
		o.PolicySyncInterval = 1 * time.Hour
	}
}

// Validate verifies that the required options are provided and valid.
func (o *Options) Validate() error {
	if o.PrivKey == nil {
		return fmt.Errorf("private key is required")
	}
	if o.Store == nil {
		return fmt.Errorf("store is required")
	}
	if o.RequiredRole == "" {
		return fmt.Errorf("RequiredRole must be specified")
	}
	return nil
}
