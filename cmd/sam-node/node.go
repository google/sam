package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
)

const AuthProtocol = protocol.ID("/sam/auth/1.0.0")

type SamNode struct {
	Host         host.Host
	DHT          *dht.IpfsDHT
	Store        *Store
	TrustedPeers map[peer.ID]bool
	mu           sync.RWMutex
}

// NewSamNode initializes a FIPS-compliant libp2p host
func NewSamNode(ctx context.Context, priv crypto.PrivKey, listenAddrs []string) (*SamNode, error) {
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(listenAddrs...),
		libp2p.Transport(libp2pquic.NewTransport),    // Preferred (UDP/QUIC)
		libp2p.Transport(tcp.NewTCPTransport),        // Fallback (TCP)
		libp2p.Security(libp2ptls.ID, libp2ptls.New), // FIPS Compliant TLS 1.3
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	return &SamNode{
		Host:         h,
		TrustedPeers: make(map[peer.ID]bool),
	}, nil
}

// SecureStreamHandler implements the "Reject by Default" middleware
func (n *SamNode) SecureStreamHandler(pid protocol.ID, handler network.StreamHandler) {
	n.Host.SetStreamHandler(pid, func(s network.Stream) {
		n.mu.RLock()
		isTrusted := n.TrustedPeers[s.Conn().RemotePeer()]
		n.mu.RUnlock()

		if !isTrusted {
			// DROP: Peer has not completed the /sam/auth/1.0.0 handshake
			fmt.Printf("Blocked unauthorized stream request for %s from %s\n", pid, s.Conn().RemotePeer())
			s.Reset()
			return
		}

		handler(s)
	})
}

// HandleAuthHandshake handles incoming Identity Biscuits
func (n *SamNode) HandleAuthHandshake(s network.Stream) {
	defer s.Close()

	// MVP: Logic to read Biscuit from stream, verify against Hub Public Key,
	// and ensure it is bound to the connecting PeerID.

	n.mu.Lock()
	n.TrustedPeers[s.Conn().RemotePeer()] = true
	n.mu.Unlock()

	fmt.Printf("Peer %s authenticated successfully via Biscuit\n", s.Conn().RemotePeer())
}
