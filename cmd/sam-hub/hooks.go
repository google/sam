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
	"sync"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

var _ connmgr.ConnectionGater = (*hubConnGate)(nil)

// hubConnGate implements libp2p ConnectionGater to enforce "Auth-or-Drop"
type hubConnGate struct {
	mu            sync.RWMutex
	authenticated map[peer.ID]bool
	lastUpdated   map[peer.ID]int64
}

func newHubConnGate() *hubConnGate {
	return &hubConnGate{
		authenticated: make(map[peer.ID]bool),
		lastUpdated:   make(map[peer.ID]int64),
	}
}

// We allow all physical connections initially but track them for "Grace Period"
func (g *hubConnGate) InterceptPeerDial(p peer.ID) bool                        { return true }
func (g *hubConnGate) InterceptAddrDial(p peer.ID, m multiaddr.Multiaddr) bool { return true }
func (g *hubConnGate) InterceptAccept(c network.ConnMultiaddrs) bool           { return true }

func (g *hubConnGate) InterceptSecured(dir network.Direction, p peer.ID, mas network.ConnMultiaddrs) bool {
	return true
}

func (g *hubConnGate) InterceptUpgraded(c network.Conn) (bool, control.DisconnectReason) {
	// We allow all connections to be upgraded. Protocol-level authorization
	// is handled at the stream level or by the watchdog.
	return true, 0
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
	wasAuth := n.hub.gater.authenticated[p]
	now := time.Now().UnixMilli()
	n.hub.gater.lastUpdated[p] = now
	delete(n.hub.gater.authenticated, p)
	n.hub.gater.mu.Unlock()

	logger.Infow("Peer disconnected", "peer_id", p, "was_authenticated", wasAuth)

	if wasAuth {
		samHubActiveNodes.Dec() // Decrement active nodes

		// Notify other hubs to clean up this peer
		n.hub.publishSyncMessage(context.Background(), &api.HubSyncMessage{
			Action:    api.HubSyncMessage_REMOVE,
			PeerId:    p.String(),
			Timestamp: now,
		})

		event := &api.MeshEvent{
			Type:      api.MeshEvent_EXIT,
			PeerId:    p.String(),
			Timestamp: time.Now().UnixMilli(),
		}
		// Sign event
		if err := n.hub.signEvent(event); err != nil {
			logger.Errorw("Failed to sign mesh event", "peer_id", p, "error", err)
		} else {
			data, err := proto.Marshal(event)
			if err != nil {
				logger.Errorw("Failed to marshal mesh event", "peer_id", p, "error", err)
				return
			}
			// Notify the mesh about the peer disconnection
			if err := n.hub.EventTopic.Publish(context.Background(), data); err != nil {
				logger.Errorw("Failed to publish mesh event", "peer_id", p, "error", err)
				return
			}
			logger.Infow("Published EXIT event", "peer_id", p)
			samHubMeshEventsTotal.WithLabelValues("EXIT").Inc()
		}
	}
}
