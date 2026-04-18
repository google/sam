// Package samnet provides the core networking substrate for SAM (Sovereign Agent Mesh).
//
// It wraps go-libp2p to deliver a zero-config, NAT-traversing, end-to-end encrypted
// mesh with Kademlia DHT discovery, Relay v2, and DCUtR hole-punching over QUIC.
// All relay traffic is E2E encrypted via TLS (QUIC-native), ensuring zero-knowledge
// relay semantics — relay nodes see only opaque ciphertext.
package samnet

import (
	"context"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// Node represents a SAM mesh node. It manages a libp2p host with QUIC transport,
// Kademlia DHT discovery, and NAT traversal via AutoNAT, Relay v2, and DCUtR
// hole-punching.
type Node interface {
	// Start initializes the libp2p host, connects to bootstrap peers,
	// and begins participating in the DHT.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the node and releases all resources.
	Stop(ctx context.Context) error

	// Host returns the underlying libp2p host.
	Host() host.Host

	// DHT returns the Kademlia DHT instance.
	DHT() *dht.IpfsDHT

	// PeerID returns this node's peer identity.
	PeerID() peer.ID

	// Addrs returns the multiaddresses this node is listening on.
	Addrs() []multiaddr.Multiaddr

	// Announce advertises a named capability to the DHT so other
	// peers can discover this node as a provider.
	Announce(ctx context.Context, capability string) error

	// Discover returns a channel of peers providing the given capability.
	Discover(ctx context.Context, capability string) (<-chan peer.AddrInfo, error)

	// PutValue stores a signed value under a DHT key using content routing.
	// Keys should be namespaced, for example: /sam/capability/weather-bot.
	PutValue(ctx context.Context, key string, value []byte) error

	// GetValue retrieves a value previously stored under a DHT key.
	GetValue(ctx context.Context, key string) ([]byte, error)

	// Connect establishes a connection to the given peer, using relay
	// fallback and hole-punching for NAT traversal.
	Connect(ctx context.Context, pi peer.AddrInfo) error
}
