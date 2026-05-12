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
	"testing"
	"time"

	"github.com/google/sam/api"
	lru "github.com/hashicorp/golang-lru/v2"
)

func TestHandleJoinEvent(t *testing.T) {
	node := &SamNode{
		knownPeers: make(map[string]bool),
	}

	event := &api.MeshEvent{
		Type:   api.MeshEvent_JOIN,
		PeerId: "12D3KooWAFv4iJst5G6MjwXhZ66K5zS1tP7A9vSg4vK8f1T7X8t9",
	}

	node.handleJoinEvent(event)

	if !node.knownPeers[event.PeerId] {
		t.Error("Expected peer to be added to knownPeers")
	}
}

func TestHandleExitEvent(t *testing.T) {
	node := &SamNode{
		knownPeers: map[string]bool{
			"12D3KooWAFv4iJst5G6MjwXhZ66K5zS1tP7A9vSg4vK8f1T7X8t9": true,
		},
	}

	event := &api.MeshEvent{
		Type:   api.MeshEvent_EXIT,
		PeerId: "12D3KooWAFv4iJst5G6MjwXhZ66K5zS1tP7A9vSg4vK8f1T7X8t9",
	}

	node.handleExitEvent(event)

	if node.knownPeers[event.PeerId] {
		t.Error("Expected peer to be removed from knownPeers")
	}
}

func TestHandleBannedEvent(t *testing.T) {
	revokedCache, _ := lru.New[string, int64](10)
	node := &SamNode{
		knownPeers: map[string]bool{
			"12D3KooWAFv4iJst5G6MjwXhZ66K5zS1tP7A9vSg4vK8f1T7X8t9": true,
		},
		revokedPeers: revokedCache,
	}

	event := &api.MeshEvent{
		Type:      api.MeshEvent_BANNED,
		PeerId:    "12D3KooWAFv4iJst5G6MjwXhZ66K5zS1tP7A9vSg4vK8f1T7X8t9",
		Timestamp: time.Now().Unix(),
	}

	node.handleBannedEvent(event)

	if node.knownPeers[event.PeerId] {
		t.Error("Expected peer to be removed from knownPeers")
	}

	if !node.revokedPeers.Contains(event.PeerId) {
		t.Error("Expected peer to be added to revokedPeers")
	}
}

func TestHandleKeyRotationEvent(t *testing.T) {
	node := &SamNode{}

	_, pub, _ := ed25519.GenerateKey(nil)

	event := &api.MeshEvent{
		Type:         api.MeshEvent_KEY_ROTATION,
		NewPublicKey: pub,
	}

	node.handleKeyRotationEvent(event)

	if len(node.trustedKeys) != 1 {
		t.Errorf("Expected 1 trusted key, got %d", len(node.trustedKeys))
	}
}

