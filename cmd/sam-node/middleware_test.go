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
	"crypto/ed25519"
	"os"
	"testing"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestAuthorize(t *testing.T) {
	dir, err := os.MkdirTemp("", "middleware-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(dir)
	}()

	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = store.Close()
	}()

	// Save a dummy policy
	policies := []string{"allow if operation($op)"}
	if err := store.SavePolicies(policies); err != nil {
		t.Fatal(err)
	}

	// Create a biscuit token
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	builder := biscuit.NewBuilder(priv)
	dummyPeer := peer.ID("dummy-peer")

	// Bind to peer
	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
	}})
	if err != nil {
		t.Fatal(err)
	}

	// Add fact and rule to make it succeed
	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "right",
		IDs:  []biscuit.Term{biscuit.String("test")},
	}})
	if err != nil {
		t.Fatal(err)
	}

	err = builder.AddAuthorityRule(biscuit.Rule{
		Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
		Body: []biscuit.Predicate{{Name: "right", IDs: []biscuit.Term{biscuit.String("test")}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	b, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	tokenBytes, err := b.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	node := &SamNode{
		Store:        store,
		HubPublicKey: pub,
	}

	req := RequestContext{
		PeerID:   dummyPeer,
		Protocol: "/test/proto",
	}

	if err := node.Authorize(tokenBytes, req); err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
}
