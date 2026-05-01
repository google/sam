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
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/time/rate"
)

const (
	// Rate limiting defaults for peers
	PeerRateLimit = 5
	PeerBurst     = 10
)

// PeerRateLimiter tracks rate limits per peer using an LRU cache.
type PeerRateLimiter struct {
	cache *lru.Cache[string, *rate.Limiter]
	mu    sync.Mutex
}

// NewPeerRateLimiter creates a new PeerRateLimiter with specified cache size.
func NewPeerRateLimiter(size int) (*PeerRateLimiter, error) {
	cache, err := lru.New[string, *rate.Limiter](size)
	if err != nil {
		return nil, err
	}
	return &PeerRateLimiter{cache: cache}, nil
}

// Allow checks if the peer is allowed to perform an action.
func (prl *PeerRateLimiter) Allow(peerID string) bool {
	prl.mu.Lock()
	defer prl.mu.Unlock()

	limiter, ok := prl.cache.Get(peerID)
	if !ok {
		limiter = rate.NewLimiter(rate.Limit(PeerRateLimit), PeerBurst)
		prl.cache.Add(peerID, limiter)
		return limiter.Allow()
	}
	return limiter.Allow()
}
