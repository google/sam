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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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

func TestCallCatalog_HTTPEndpoint(t *testing.T) {
	_, pub, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	pid, _ := peer.IDFromPublicKey(pub)
	idStr := pid.String()

	cannedJSON := fmt.Sprintf(`[{"Type":1,"Name":"github-tools","PeerID":%q}]`, idStr)

	server := mcp.NewServer(&mcp.Implementation{Name: "test-catalog", Version: "0.1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "query_catalog"}, func(_ context.Context, _ *mcp.CallToolRequest, _ map[string]any) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: cannedJSON}}}, nil, nil
	})
	streamableHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return server
	}, nil)

	mux := http.NewServeMux()
	mux.Handle("/mcp", streamableHandler)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	n := &SamNode{BoundHTTPAddr: "127.0.0.1:9999"}
	res, err := n.callCatalog(context.Background(), catalogEndpoint{url: ts.URL}, map[string]string{"type": "mcp", "name": "github-tools"})
	if err != nil {
		t.Fatalf("callCatalog: %v", err)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content type: got %T, want *mcp.TextContent", res.Content[0])
	}
	providers, err := catalogEntriesToProviders(n, text.Text, "mcp")
	if err != nil {
		t.Fatalf("map providers: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("want 1 provider, got %d", len(providers))
	}
	if providers[0].PeerId != idStr {
		t.Errorf("PeerId = %q, want %q", providers[0].PeerId, idStr)
	}
	if !strings.Contains(providers[0].LocalProxyUrl, idStr) {
		t.Errorf("LocalProxyUrl %q does not contain %q", providers[0].LocalProxyUrl, idStr)
	}
	if providers[0].SrvName != "github-tools" {
		t.Errorf("SrvName = %q, want github-tools", providers[0].SrvName)
	}
}
