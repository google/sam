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
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
)

func TestHandleBannedEvent(t *testing.T) {
	revokedCache, _ := lru.New[string, int64](10)
	node := &SamNode{
		revokedPeers: revokedCache,
	}

	event := &api.MeshEvent{
		Type:      api.MeshEvent_BANNED,
		PeerId:    "12D3KooWAFv4iJst5G6MjwXhZ66K5zS1tP7A9vSg4vK8f1T7X8t9",
		Timestamp: time.Now().UnixMilli(),
	}

	node.handleBannedEvent(event)

	if !node.revokedPeers.Contains(event.PeerId) {
		t.Error("Expected peer to be added to revokedPeers")
	}
}

func TestHandleKeyRotationEvent(t *testing.T) {
	node := &SamNode{}

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	event := &api.MeshEvent{
		Type:         api.MeshEvent_KEY_ROTATION,
		NewPublicKey: pub,
		Timestamp:    time.Now().UnixMilli(),
	}

	node.handleKeyRotationEvent(event)

	if len(node.trustedKeys) != 1 {
		t.Errorf("Expected 1 trusted key, got %d", len(node.trustedKeys))
	}
}

func TestNewSamNode_FailsAuth(t *testing.T) {
	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	hubAddrs := []multiaddr.Multiaddr{multiaddr.StringCast("/ip4/127.0.0.1/tcp/9999")}
	store, _ := NewStore(t.TempDir()) // We need a valid store

	_, err := NewSamNode(context.Background(), priv, nil, hubAddrs, store, "test", "10s", []string{"/ip4/127.0.0.1/tcp/0"}, false, nil, 0, false)
	if err == nil {
		t.Fatal("Expected NewSamNode to fail when it cannot connect to the hub")
	}
	if !strings.Contains(err.Error(), "failed to authenticate with any hub") {
		t.Fatalf("Expected 'failed to authenticate with any hub' error, got %v", err)
	}
}

func TestStartRenewalLoop_ExpiredAndFails(t *testing.T) {
	if os.Getenv("BE_CRASHER") == "1" {
		store, _ := NewStore(t.TempDir())
		// Set expiration to the past
		_ = store.SaveIdentityExpiration(time.Now().Add(-1 * time.Hour).Unix())

		node := &SamNode{
			Store: store,
		}

		// Run the renewal loop. Since there's no JWT/Issuer provided, it fails to renew.
		// It will see that it's expired and it failed to renew, so it will log.Fatalf
		node.StartRenewalLoop(context.Background(), "", "", "", "")
		time.Sleep(5 * time.Second)
		os.Exit(0) // should not be reached
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestStartRenewalLoop_ExpiredAndFails")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return // Successful fatal exit
	}
	t.Fatalf("process ran with err %v, want exit status 1 (fatal crash)", err)
}
