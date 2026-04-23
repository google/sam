package main

import (
	"fmt"
	"sync"
	"time"

	p2phttp "github.com/libp2p/go-libp2p-http"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

var _ connmgr.ConnectionGater = (*hubConnGate)(nil)

// hubConnGate implements libp2p ConnectionGater to enforce "Auth-or-Drop"
type hubConnGate struct {
	mu            sync.RWMutex
	authenticated map[peer.ID]bool
	pending       map[peer.ID]time.Time
}

func newHubConnGate() *hubConnGate {
	return &hubConnGate{
		authenticated: make(map[peer.ID]bool),
		pending:       make(map[peer.ID]time.Time),
	}
}

// We allow all physical connections initially but track them for "Grace Period"
func (g *hubConnGate) InterceptPeerDial(p peer.ID) bool                        { return true }
func (g *hubConnGate) InterceptAddrDial(p peer.ID, m multiaddr.Multiaddr) bool { return true }
func (g *hubConnGate) InterceptAccept(c network.ConnMultiaddrs) bool           { return true }

func (g *hubConnGate) InterceptSecured(dir network.Direction, p peer.ID, mas network.ConnMultiaddrs) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.authenticated[p] {
		g.pending[p] = time.Now()
	}
	return true
}

func (g *hubConnGate) InterceptUpgraded(c network.Conn) (bool, control.DisconnectReason) {
	protocolID := c.ConnState().StreamMultiplexer

	// Always allow the OIDC bridge protocol and basic identify
	if protocolID == p2phttp.DefaultP2PProtocol || protocolID == "/ipfs/id/1.0.0" {
		return true, 0
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	// REJECT BY DEFAULT: If not authenticated via OIDC, block any other protocol
	return g.authenticated[c.RemotePeer()], control.DisconnectReason(0)
}

var _ network.Notifiee = (*notifier)(nil)

type notifier struct {
	hub *Hub
}

func (n *notifier) Listen(network.Network, multiaddr.Multiaddr)      {}
func (n *notifier) ListenClose(network.Network, multiaddr.Multiaddr) {}
func (n *notifier) Connected(network.Network, network.Conn)          {}
func (n *notifier) Disconnected(_ network.Network, c network.Conn) {
	p := c.RemotePeer()
	n.hub.gater.mu.Lock()
	delete(n.hub.gater.authenticated, p)
	delete(n.hub.gater.pending, p)
	n.hub.gater.mu.Unlock()
	fmt.Printf("[Mesh] Peer %s disconnected. Authorization cleared.\n", p)
}
