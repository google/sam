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
	"crypto/ed25519"
	"fmt"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

const AuthProtocolID = protocol.ID("/sam/auth/1.0.0")

type SamNode struct {
	Host         host.Host
	DHT          *dht.IpfsDHT
	PubSub       *pubsub.PubSub
	Store        *Store
	HubPublicKey ed25519.PublicKey
	HubPeerID    peer.ID
}

// NewSamNode creates a new Agent instance secured with the 4-layer pipeline.
func NewSamNode(ctx context.Context, privKey crypto.PrivKey, hubPubKey ed25519.PublicKey, hubAddrs []multiaddr.Multiaddr, store *Store) (*SamNode, error) {
	node := &SamNode{
		Store:        store,
		HubPublicKey: hubPubKey,
	}

	// Layer 2: Attach the Bouncer (Gater)
	gater := &nodeConnGate{node: node}

	// Layer 1: Establish FIPS-compliant Transports
	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.ConnectionGater(gater),
	)
	if err != nil {
		return nil, err
	}
	node.Host = h

	// Initialize Rendezvous (DHT Client)
	kdht, err := dht.New(ctx, h, dht.Mode(dht.ModeClient))
	if err != nil {
		return nil, err
	}
	node.DHT = kdht

	// Bootstrap: Connect to the Hub
	for _, addr := range hubAddrs {
		addrInfo, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil || addrInfo == nil {
			// Try to connect without Peer ID in address
			addrInfo = &peer.AddrInfo{
				Addrs: []multiaddr.Multiaddr{addr},
			}
			fmt.Println("[Warning] Connecting to hub without Peer ID verification in address.")
		}
		if err := h.Connect(ctx, *addrInfo); err != nil {
			fmt.Printf("Warning: Failed to bootstrap to hub %s: %v\n", addr, err)
		} else {
			if addrInfo.ID == "" {
				// Discover Peer ID from connection
				for _, c := range h.Network().Conns() {
					if c.RemoteMultiaddr().Equal(addr) {
						node.HubPeerID = c.RemotePeer()
						fmt.Printf("Connected to hub (discovered PeerID): %s\n", node.HubPeerID)
						break
					}
				}
			} else {
				node.HubPeerID = addrInfo.ID
				fmt.Printf("Connected to hub: %s\n", addrInfo.ID)
			}
			break
		}
	}

	// Initialize Gossipsub for Hub Events
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, err
	}
	node.PubSub = ps

	// Listen for Network Evictions/Revocations from the Hub
	go node.listenForHubEvents(ctx)

	// Layer 3: Open the Lobby Door (Auth Protocol is bypassed by Layer 4)
	node.WrapSecurely(AuthProtocolID, node.HandleAuthHandshake)

	return node, nil
}

// listenForHubEvents listens to the topic established by the Hub
func (n *SamNode) listenForHubEvents(ctx context.Context) {
	topic, err := n.PubSub.Join(api.GossipEvents)
	if err != nil {
		return
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return
	}

	for {
		msg, err := sub.Next(ctx)
		if err != nil {
			return
		}
		var revMsg api.RevocationMsg
		if err := proto.Unmarshal(msg.Data, &revMsg); err != nil {
			fmt.Printf("[Mesh Event] Failed to unmarshal revocation message from %s: %v\n", msg.ReceivedFrom, err)
			continue
		}
		fmt.Printf("[Mesh Event] Received Hub update from %s for target %s\n", msg.ReceivedFrom, revMsg.TargetPeerId)
	}
}

// HandleAuthHandshake is the core libp2p stream handler for /sam/auth/1.0.0.
// This is the "Admission Office" of the mesh node.
func (n *SamNode) HandleAuthHandshake(s network.Stream) {
	defer func() {
		if err := s.Close(); err != nil {
			fmt.Printf("Failed to close auth stream: %v\n", err)
		}
	}()
	remotePeer := s.Conn().RemotePeer()

	reader := msgio.NewVarintReaderSize(s, 1024*64)
	msg, err := reader.ReadMsg()
	if err != nil {
		fmt.Printf("[AuthN] Failed to read handshake from %s: %v\n", remotePeer, err)
		return
	}
	defer reader.ReleaseMsg(msg)

	var exchange api.AuthEnvelope
	if err := proto.Unmarshal(msg, &exchange); err != nil {
		fmt.Printf("[AuthN] Invalid protobuf from %s\n", remotePeer)
		return
	}

	// 2. Unmarshal and verify token format
	b, err := biscuit.Unmarshal(exchange.Biscuit)
	if err != nil {
		fmt.Printf("[AuthN] Malformed biscuit from %s\n", remotePeer)
		return
	}

	// 3. Verify signature chain against the trusted Hub key.
	authorizer, err := b.Authorizer(n.HubPublicKey)
	if err != nil {
		fmt.Printf("[AuthN] Signature verification setup failed for %s: %v\n", remotePeer, err)
		return
	}
	if err := authorizer.Authorize(); err != nil {
		fmt.Printf("[AuthN] Authorization failed for %s: %v\n", remotePeer, err)
		return
	}

	// 4. Enforce hardware binding: token must include node(<remotePeerID>)
	boundFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}
	if _, err := b.GetBlockID(boundFact); err != nil {
		fmt.Printf("[AuthN] Token is not bound to peer %s\n", remotePeer)
		return
	}

	// Query for the standard facts we mapped in the Hub
	// user_id, user_email, group, mesh_id
	// Note: We use the authorizer to extract these values from the Datalog state
	identity := VerifiedIdentity{
		RawBiscuit: exchange.Biscuit,
		// In a full implementation, you would use authorizer.Query()
		// to extract specific strings like user_id and group.
		NodeID:    remotePeer.String(), // Placeholder for Datalog query result
		UserID:    "extracted_id",      // Placeholder for Datalog query result
		UserEmail: "extracted_email",   // Placeholder for Datalog query result
		MeshID:    "extracted_mesh",    // Placeholder for Datalog query result
	}

	// 5. Save to the persistent session cache (BoltDB)
	// Once saved here, the ConnectionGater and Middleware will "recognize" this peer.
	if err := n.Store.SaveVerifiedIdentity(remotePeer, identity); err != nil {
		fmt.Printf("[AuthN] Store error for %s: %v\n", remotePeer, err)
		return
	}

	fmt.Printf("[AuthN] Successfully authenticated peer %s (%s)\n", remotePeer, identity.UserEmail)
}


