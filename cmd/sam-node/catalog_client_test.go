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
	"fmt"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestCatalogEntriesToProviders(t *testing.T) {
	priv, pub, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	_ = priv
	pid, _ := peer.IDFromPublicKey(pub)
	idStr := pid.String()

	n := &SamNode{BoundHTTPAddr: "127.0.0.1:9999"}
	raw := fmt.Sprintf(`[{"Type":1,"Name":"github-tools","PeerID":%q,"Addrs":["/ip4/1.2.3.4/tcp/1"],"Expiry":"2030-01-01T00:00:00Z"}]`, idStr)
	got, err := catalogEntriesToProviders(n, raw, "mcp")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 provider, got %d", len(got))
	}
	if got[0].PeerId != idStr {
		t.Fatalf("PeerId: want %q, got %q", idStr, got[0].PeerId)
	}
	if !strings.Contains(got[0].LocalProxyUrl, idStr) {
		t.Fatalf("LocalProxyUrl %q does not contain peer id %q", got[0].LocalProxyUrl, idStr)
	}
	if got[0].SrvName != "github-tools" {
		t.Fatalf("SrvName: want %q, got %q", "github-tools", got[0].SrvName)
	}
}

func TestCatalogEntriesToProvidersBadPeerSkipped(t *testing.T) {
	n := &SamNode{BoundHTTPAddr: "127.0.0.1:9999"}
	raw := `[{"Type":1,"Name":"bad-svc","PeerID":"not-a-peer-id"}]`
	got, err := catalogEntriesToProviders(n, raw, "mcp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 providers for bad peer id, got %d", len(got))
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
