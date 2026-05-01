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
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"go.etcd.io/bbolt"
)

func TestConnectionGater(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Logf("failed to close store: %v", err)
		}
	}()

	cache, err := lru.New[string, int64](100)
	if err != nil {
		t.Fatal(err)
	}

	node := &SamNode{
		Store:        store,
		revokedPeers: cache,
	}
	gater := &nodeConnGate{node: node}

	// Generate test peer IDs
	priv1, _, _ := crypto.GenerateEd25519Key(nil)
	peer1, _ := peer.IDFromPrivateKey(priv1)

	priv2, _, _ := crypto.GenerateEd25519Key(nil)
	peer2, _ := peer.IDFromPrivateKey(priv2)

	priv3, _, _ := crypto.GenerateEd25519Key(nil)
	peer3, _ := peer.IDFromPrivateKey(priv3)

	// Case 1: Peer is not banned
	if !gater.InterceptPeerDial(peer1) {
		t.Errorf("expected InterceptPeerDial to allow peer1")
	}
	if !gater.InterceptSecured(network.DirInbound, peer1, nil) {
		t.Errorf("expected InterceptSecured to allow peer1")
	}

	// Case 2: Peer is in revoked cache
	node.revokedPeers.Add(peer2.String(), time.Now().Unix())
	if gater.InterceptPeerDial(peer2) {
		t.Errorf("expected InterceptPeerDial to deny peer2 (in revoked cache)")
	}

	if gater.InterceptSecured(network.DirInbound, peer2, nil) {
		t.Errorf("expected InterceptSecured to deny peer2 (in revoked cache)")
	}

	// Case 3: Peer is in persistent store (banned)
	err = store.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketBannedPeers))
		return b.Put([]byte(peer3.String()), []byte("true"))
	})
	if err != nil {
		t.Fatal(err)
	}

	if gater.InterceptPeerDial(peer3) {
		t.Errorf("expected InterceptPeerDial to deny peer3 (in store)")
	}
	if gater.InterceptSecured(network.DirInbound, peer3, nil) {
		t.Errorf("expected InterceptSecured to deny peer3 (in store)")
	}
}
