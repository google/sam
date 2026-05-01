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
)

func TestPeerRateLimiter(t *testing.T) {
	prl, err := NewPeerRateLimiter(2) // Small size to test eviction
	if err != nil {
		t.Fatal(err)
	}

	peer1 := "peer1"
	peer2 := "peer2"
	peer3 := "peer3"

	// Test new peer
	if !prl.Allow(peer1) {
		t.Error("Expected new peer to be allowed")
	}

	// Test burst
	for i := 0; i < PeerBurst-1; i++ {
		if !prl.Allow(peer1) {
			t.Errorf("Expected burst request %d to be allowed", i)
		}
	}

	// Exceed burst
	count := 0
	for i := 0; i < 20; i++ {
		if prl.Allow(peer1) {
			count++
		}
	}
	t.Logf("Allowed %d more requests after burst loop", count)
	
	if count > 0 {
		t.Errorf("Expected requests exceeding burst to be rejected, but allowed %d more", count)
	}

	// Test peer2
	if !prl.Allow(peer2) {
		t.Error("Expected peer2 to be allowed")
	}

	// Test eviction
	// Current cache: peer1, peer2
	if !prl.Allow(peer3) {
		t.Error("Expected peer3 to be allowed")
	}
	// Cache should have evicted peer1 or peer2 (LRU).
	// Since we used peer1 and then peer2, peer1 is the oldest!
	// So peer1 should be evicted!
	
	// Let's verify peer1 was evicted by checking if it gets a new limiter (allowed again!)
	if !prl.Allow(peer1) {
		t.Error("Expected evicted peer1 to be allowed again with new limiter")
	}
}
