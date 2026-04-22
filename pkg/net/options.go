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

package samnet

import (
	cryptorand "crypto/rand"
	"fmt"
	"log/slog"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
)

// DHTMode controls how the node participates in the Kademlia DHT.
type DHTMode int

const (
	// DHTModeAuto automatically switches between client and server based on
	// the node's reachability (NAT status).
	DHTModeAuto DHTMode = iota
	// DHTModeServer always participates as a full DHT server.
	DHTModeServer
	// DHTModeClient always participates as a DHT client only.
	DHTModeClient

	DefaultRelayFallbackHost   = "app.sam-mesh.dev"
	DefaultRendezvousNamespace = "app.sam-mesh.dev"
)

// Options configures a SAM mesh node.
type Options struct {
	// PrivateKey is the Ed25519 identity key. Generated if nil.
	PrivateKey crypto.PrivKey
	// ListenAddrs are the multiaddresses to listen on.
	ListenAddrs []multiaddr.Multiaddr
	// BootstrapPeers are the initial peers to connect to on startup.
	// Each address must include the /p2p/<peerID> component.
	BootstrapPeers []multiaddr.Multiaddr
	// DHTMode controls DHT participation level.
	DHTMode DHTMode
	// EnableRelayService runs a circuit relay v2 service, allowing other
	// peers to relay through this node.
	EnableRelayService bool
	// UserAgent is the libp2p user-agent string.
	UserAgent string
	// Logger is the structured logger. Defaults to slog.Default().
	Logger *slog.Logger
	// FederationID scopes DHT participation to the single SAM namespace.
	// Runtime enforces the default value for all nodes.
	FederationID string
	// RelayFallbackHost is the default host hint for relay bootstrap.
	RelayFallbackHost string
	// RendezvousNamespace scopes capability discovery advertisements.
	RendezvousNamespace string
}

// Option is a functional option for node configuration.
type Option func(*Options)

// DefaultOptions returns production defaults: QUIC on all interfaces,
// auto DHT mode, and standard user-agent.
func DefaultOptions() Options {
	quicV1, _ := multiaddr.NewMultiaddr("/ip4/0.0.0.0/udp/0/quic-v1")
	quicV1v6, _ := multiaddr.NewMultiaddr("/ip6/::/udp/0/quic-v1")
	tcpV4, _ := multiaddr.NewMultiaddr("/ip4/0.0.0.0/tcp/0")
	tcpV6, _ := multiaddr.NewMultiaddr("/ip6/::/tcp/0")
	return Options{
		ListenAddrs:         []multiaddr.Multiaddr{quicV1, quicV1v6, tcpV4, tcpV6},
		DHTMode:             DHTModeAuto,
		UserAgent:           "sam/0.1.0",
		Logger:              slog.Default(),
		FederationID:        "default",
		RelayFallbackHost:   DefaultRelayFallbackHost,
		RendezvousNamespace: DefaultRendezvousNamespace,
	}
}

func (o *Options) validate() error {
	if o.PrivateKey == nil {
		key, err := GenerateKey()
		if err != nil {
			return fmt.Errorf("generating default key: %w", err)
		}
		o.PrivateKey = key
	}
	if len(o.ListenAddrs) == 0 {
		return fmt.Errorf("at least one listen address required")
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.FederationID == "" {
		o.FederationID = "default"
	}
	if o.RelayFallbackHost == "" {
		o.RelayFallbackHost = DefaultRelayFallbackHost
	}
	if o.RendezvousNamespace == "" {
		o.RendezvousNamespace = DefaultRendezvousNamespace
	}
	return nil
}

// GenerateKey creates a new Ed25519 private key suitable for use as a peer identity.
func GenerateKey() (crypto.PrivKey, error) {
	priv, _, err := crypto.GenerateEd25519Key(cryptorand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ed25519 key: %w", err)
	}
	return priv, nil
}

// WithPrivateKey sets the node's Ed25519 identity key.
func WithPrivateKey(key crypto.PrivKey) Option {
	return func(o *Options) { o.PrivateKey = key }
}

// WithListenAddrs sets the multiaddresses to listen on.
func WithListenAddrs(addrs ...multiaddr.Multiaddr) Option {
	return func(o *Options) { o.ListenAddrs = addrs }
}

// WithBootstrapPeers sets initial peers to connect during Start.
func WithBootstrapPeers(addrs ...multiaddr.Multiaddr) Option {
	return func(o *Options) { o.BootstrapPeers = addrs }
}

// WithDHTMode sets the DHT participation mode.
func WithDHTMode(mode DHTMode) Option {
	return func(o *Options) { o.DHTMode = mode }
}

// WithRelayService enables the circuit relay v2 service.
func WithRelayService() Option {
	return func(o *Options) { o.EnableRelayService = true }
}

// WithFederation keeps API compatibility but federation is fixed at runtime.
func WithFederation(_ string) Option {
	return func(o *Options) { o.FederationID = "default" }
}

// WithLogger sets a structured logger for the node.

func WithLogger(l *slog.Logger) Option {
	return func(o *Options) { o.Logger = l }
}

// WithUserAgent sets the libp2p user-agent string.
func WithUserAgent(ua string) Option {
	return func(o *Options) { o.UserAgent = ua }
}

// WithRendezvousNamespace sets the discovery rendezvous namespace.
func WithRendezvousNamespace(ns string) Option {
	return func(o *Options) { o.RendezvousNamespace = ns }
}

// WithRelayFallbackHost sets the relay host hint used in logs and defaults.
func WithRelayFallbackHost(host string) Option {
	return func(o *Options) { o.RelayFallbackHost = host }
}
