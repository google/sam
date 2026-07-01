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

package catalog

import (
	"sync"
	"time"

	"github.com/google/sam/api"
)

type Entry struct {
	Type   api.ServiceType
	Name   string
	PeerID string
	Addrs  []string
	Expiry time.Time
}

type Store struct {
	mu      sync.RWMutex
	entries map[string]Entry
}

func New() *Store { return &Store{entries: map[string]Entry{}} }

func key(t api.ServiceType, name, peerID string) string {
	return t.String() + "|" + name + "|" + peerID
}

// Upsert inserts or refreshes an entry, setting Expiry from the announce TTL.
func (s *Store) Upsert(a *api.ServiceAnnounce, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key(a.Type, a.Name, a.PeerId)] = Entry{
		Type: a.Type, Name: a.Name, PeerID: a.PeerId, Addrs: a.Addrs,
		Expiry: now.Add(time.Duration(a.TtlMs) * time.Millisecond),
	}
}

// List returns entries matching the optional type and name filters.
func (s *Store) List(typeFilter api.ServiceType, name string) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Entry{}
	for _, e := range s.entries {
		if typeFilter != api.ServiceType_SERVICE_TYPE_UNSPECIFIED && e.Type != typeFilter {
			continue
		}
		if name != "" && e.Name != name {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Sweep removes expired entries and returns the count removed.
func (s *Store) Sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, e := range s.entries {
		if now.After(e.Expiry) {
			delete(s.entries, k)
			n++
		}
	}
	return n
}
