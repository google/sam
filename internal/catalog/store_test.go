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
	"testing"
	"time"

	"github.com/google/sam/api"
)

func ann(name string, ttlMs int64, ts int64) *api.ServiceAnnounce {
	return &api.ServiceAnnounce{
		Type: api.ServiceType_SERVICE_TYPE_MCP, Name: name, PeerId: "p-" + name,
		Addrs: []string{"/ip4/127.0.0.1/tcp/1"}, Timestamp: ts, TtlMs: ttlMs,
	}
}

func TestUpsertAndList(t *testing.T) {
	s := New()
	now := time.UnixMilli(1000)
	s.Upsert(ann("a", 60000, 1000), now)
	s.Upsert(ann("b", 60000, 1000), now)
	if got := s.List(api.ServiceType_SERVICE_TYPE_MCP, ""); len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
	if got := s.List(api.ServiceType_SERVICE_TYPE_MCP, "a"); len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("name filter failed: %+v", got)
	}
	if got := s.List(api.ServiceType_SERVICE_TYPE_INFERENCE, ""); len(got) != 0 {
		t.Fatalf("type filter failed: %+v", got)
	}
}

func TestUpsertRefreshesExpiry(t *testing.T) {
	s := New()
	s.Upsert(ann("a", 60000, 1000), time.UnixMilli(1000)) // expiry 61000
	s.Upsert(ann("a", 60000, 1000), time.UnixMilli(5000)) // refresh -> 65000
	if n := s.Sweep(time.UnixMilli(62000)); n != 0 {
		t.Fatalf("entry should have been refreshed, swept %d", n)
	}
	if got := s.List(api.ServiceType_SERVICE_TYPE_MCP, ""); len(got) != 1 {
		t.Fatalf("want 1 after refresh, got %d", len(got))
	}
}

func TestSweepEvictsExpired(t *testing.T) {
	s := New()
	s.Upsert(ann("a", 1000, 1000), time.UnixMilli(1000)) // expiry 2000
	if n := s.Sweep(time.UnixMilli(3000)); n != 1 {
		t.Fatalf("want 1 swept, got %d", n)
	}
	if got := s.List(api.ServiceType_SERVICE_TYPE_UNSPECIFIED, ""); len(got) != 0 {
		t.Fatalf("want empty after sweep, got %d", len(got))
	}
}
