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

func TestCatalogEntriesToProviders(t *testing.T) {
	n := &SamNode{BoundHTTPAddr: "127.0.0.1:9999"}
	raw := `[{"Type":1,"Name":"github-tools","PeerID":"12D3KooWtest","Addrs":["/ip4/1.2.3.4/tcp/1"],"Expiry":"2030-01-01T00:00:00Z"}]`
	got, err := catalogEntriesToProviders(n, raw, "mcp")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 provider, got %d", len(got))
	}
	if got[0].PeerId != "12D3KooWtest" || got[0].SrvName != "github-tools" || got[0].LocalProxyUrl == "" {
		t.Fatalf("bad mapping: %+v", got[0])
	}
}

func TestCatalogEntriesToProvidersEmpty(t *testing.T) {
	n := &SamNode{BoundHTTPAddr: "127.0.0.1:9999"}
	got, err := catalogEntriesToProviders(n, `[]`, "mcp")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0, got %d", len(got))
	}
}
