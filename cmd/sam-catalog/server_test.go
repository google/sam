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
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/catalog"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestQueryCatalogTool(t *testing.T) {
	store := catalog.New()
	// Pre-seed one entry.
	store.Upsert(&api.ServiceAnnounce{
		Type:   api.ServiceType_SERVICE_TYPE_MCP,
		Name:   "tool-a",
		PeerId: "peer123",
		TtlMs:  60000,
	}, time.Now())

	ts := httptest.NewServer(newCatalogMCPHandler(store))
	defer ts.Close()

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.1.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			t.Logf("close session: %v", err)
		}
	}()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "query_catalog",
		Arguments: map[string]any{"type": "mcp"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	var text string
	for _, c := range result.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text = tc.Text
			break
		}
	}
	if text == "" {
		t.Fatal("empty text content in response")
	}

	var entries []catalog.Entry
	if err := json.Unmarshal([]byte(text), &entries); err != nil {
		t.Fatalf("unmarshal entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d: %s", len(entries), text)
	}
	if entries[0].Name != "tool-a" {
		t.Errorf("expected name=tool-a, got %s", entries[0].Name)
	}
	if entries[0].PeerID != "peer123" {
		t.Errorf("expected peerID=peer123, got %s", entries[0].PeerID)
	}
}
