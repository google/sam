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

package node

import (
	"context"
	"crypto/ed25519"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/google/sam/api"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
)

func TestHandleBannedEvent(t *testing.T) {
	revokedCache, _ := lru.New[string, int64](10)
	node := &SamNode{
		revokedPeers:   revokedCache,
		BiscuitTimeout: 500 * time.Millisecond,
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
	node := &SamNode{BiscuitTimeout: 500 * time.Millisecond}

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

func TestStartRenewalLoop_ExpiredAndFails(t *testing.T) {
	if os.Getenv("BE_CRASHER") == "1" {
		store, _ := NewStore(t.TempDir())
		// Set expiration to the past
		_ = store.SaveIdentityExpiration(time.Now().Add(-1 * time.Hour).Unix())

		node := &SamNode{
			BiscuitTimeout: 500 * time.Millisecond,
			Store:          store,
		}

		// Run the renewal loop. Since there's no JWT/Issuer provided, it fails to renew.
		// It will see that it's expired and it failed to renew, so it will log.Fatalf
		node.StartRenewalLoop(context.Background(), "", "", "", "")
		time.Sleep(2 * time.Second)
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

func TestConnectionMonitor_CrashesAfterFailures(t *testing.T) {
	if os.Getenv("BE_CRASHER_MONITOR") == "1" {
		priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		store, _ := NewStore(t.TempDir())
		node, err := NewSamNode(Options{
			PrivKey:           priv,
			HubAddrs:          nil,
			Store:             store,
			MeshID:            "test",
			DiscoveryInterval: "10s",
			ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
			EnableRelay:       false,
			NodeConfig:        nil,
			KeyGracePeriod:    0,
			AllowLoopback:     false,
			MonitorBootstrap:  2 * time.Minute,
			MonitorInterval:   1 * time.Minute,
		})
		if err != nil {
			os.Exit(0) // Ignore NewSamNode errors for this crasher
		}
		if err := node.Start(context.Background()); err != nil {
			os.Exit(0)
		}

		// Use very short durations
		node.startConnectionMonitor(context.Background(), 10*time.Millisecond, 10*time.Millisecond, 3)
		time.Sleep(1 * time.Second)
		os.Exit(0) // should not be reached
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestConnectionMonitor_CrashesAfterFailures")
	cmd.Env = append(os.Environ(), "BE_CRASHER_MONITOR=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return // Successful fatal exit
	}
	t.Fatalf("process ran with err %v, want exit status 1 (fatal crash)", err)
}

func TestNewSamNode_Validation(t *testing.T) {
	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	store, _ := NewStore(t.TempDir())
	defer func() { _ = store.Close() }()

	t.Run("nil PrivKey", func(t *testing.T) {
		_, err := NewSamNode(Options{
			PrivKey: nil,
			Store:   store,
		})
		if err == nil || err.Error() != "private key is required" {
			t.Errorf("expected 'private key is required' error, got: %v", err)
		}
	})

	t.Run("nil Store", func(t *testing.T) {
		_, err := NewSamNode(Options{
			PrivKey: priv,
			Store:   nil,
		})
		if err == nil || err.Error() != "store is required" {
			t.Errorf("expected 'store is required' error, got: %v", err)
		}
	})
}

func TestNewSamNode_DHTOptions(t *testing.T) {
	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	store, _ := NewStore(t.TempDir())
	defer func() { _ = store.Close() }()

	opts := Options{
		PrivKey:              priv,
		Store:                store,
		ListenAddrs:          []string{"/ip4/127.0.0.1/tcp/0"},
		DHTProviderAddrTTL:   10 * time.Second,
		DHTMaxRecordAge:      15 * time.Second,
		DHTLookupLimit:       50,
		DiscoveryConcurrency: 5,
	}

	node, err := NewSamNode(opts)
	if err != nil {
		t.Fatalf("failed to create node with DHT options: %v", err)
	}

	if node.config.DHTProviderAddrTTL != 10*time.Second {
		t.Errorf("expected DHTProviderAddrTTL to be 10s, got %v", node.config.DHTProviderAddrTTL)
	}
	if node.config.DHTMaxRecordAge != 15*time.Second {
		t.Errorf("expected DHTMaxRecordAge to be 15s, got %v", node.config.DHTMaxRecordAge)
	}
	if node.config.DHTLookupLimit != 50 {
		t.Errorf("expected DHTLookupLimit to be 50, got %d", node.config.DHTLookupLimit)
	}
	if node.config.DiscoveryConcurrency != 5 {
		t.Errorf("expected DiscoveryConcurrency to be 5, got %d", node.config.DiscoveryConcurrency)
	}
}
