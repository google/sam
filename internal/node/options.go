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
	if len(o.ListenAddrs) == 0 {
		o.ListenAddrs = []string{"/ip4/0.0.0.0/udp/5001/quic-v1", "/ip4/0.0.0.0/tcp/5002"}
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
	return nil
}
