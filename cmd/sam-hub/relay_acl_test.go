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
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func TestRelayACL_AllowConnect(t *testing.T) {
	hub := &Hub{}
	acl := &relayACL{hub: hub}

	srcPeer := peer.ID("src-peer")
	destPeer := peer.ID("dest-peer")
	srcAddr, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1234")

	// Neither is authenticated
	if acl.AllowConnect(srcPeer, srcAddr, destPeer) {
		t.Errorf("Expected AllowConnect to return false when dest is not authenticated")
	}

	// Src is authenticated, dest is not -> should fail
	hub.authenticatedPeers.Store(srcPeer, true)
	if acl.AllowConnect(srcPeer, srcAddr, destPeer) {
		t.Errorf("Expected AllowConnect to return false when dest is not authenticated, even if src is")
	}

	// Dest is authenticated, src is not -> should succeed
	hub.authenticatedPeers.Delete(srcPeer)
	hub.authenticatedPeers.Store(destPeer, true)
	if !acl.AllowConnect(srcPeer, srcAddr, destPeer) {
		t.Errorf("Expected AllowConnect to return true when dest is authenticated")
	}
}

func TestRelayACL_AllowReserve(t *testing.T) {
	hub := &Hub{}
	acl := &relayACL{hub: hub}

	peerID := peer.ID("some-peer")
	addr, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1234")

	if acl.AllowReserve(peerID, addr) {
		t.Errorf("Expected AllowReserve to return false when peer is not authenticated")
	}

	hub.authenticatedPeers.Store(peerID, true)
	if !acl.AllowReserve(peerID, addr) {
		t.Errorf("Expected AllowReserve to return true when peer is authenticated")
	}
}
