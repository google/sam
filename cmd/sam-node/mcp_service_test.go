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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// newFakeMCPHandler returns an http.Handler serving a tiny MCP server over
// streamable-http with the given tools registered.
func newFakeMCPHandler(t *testing.T, tools []*mcp.Tool) http.Handler {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "0.0.1"}, nil)
	for _, tool := range tools {
		toolCopy := tool
		srv.AddTool(toolCopy, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "fake-result:" + toolCopy.Name}},
			}, nil
		})
	}
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
}

func TestMCPService_InitURL_AggregatesNamespacedTools(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tools := []*mcp.Tool{
		{Name: "review_pr", Description: "Run a code review", InputSchema: map[string]any{"type": "object"}},
		{Name: "add_comment", Description: "Add a comment", InputSchema: map[string]any{"type": "object"}},
	}
	upstream := httptest.NewServer(newFakeMCPHandler(t, tools))
	defer upstream.Close()

	svc := &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: upstream.URL},
	}}

	if err := svc.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = svc.Teardown() }()

	got := svc.Tools()
	if len(got) != 2 {
		t.Fatalf("Tools length: got %d, want 2", len(got))
	}
	names := map[string]bool{}
	for _, tool := range got {
		names[tool.Name] = true
	}
	for _, want := range []string{"code-reviewer.review_pr", "code-reviewer.add_comment"} {
		if !names[want] {
			t.Errorf("expected namespaced tool %q in %v", want, names)
		}
	}
	if svc.handler == nil {
		t.Errorf("Handler is nil after Init")
	}
}

func TestMCPService_InitURL_InvalidURLRollsBack(t *testing.T) {
	svc := &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "broken"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: "::not a url::"},
	}}
	if err := svc.Init(context.Background()); err == nil {
		t.Fatal("Init: expected error for invalid URL, got nil")
	}
	if svc.cmd != nil {
		t.Errorf("rollback failed: cmd should be nil, got %v", svc.cmd)
	}
	if svc.session != nil {
		t.Errorf("rollback failed: session should be nil")
	}
}

func TestMCPService_InitURL_ListToolsFailureBestEffort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Handler that 500s on every request: Connect may succeed, ListTools won't.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()

	svc := &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "broken"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: upstream.URL},
	}}
	// Init may return nil (best-effort) OR an error from Connect. Both are acceptable.
	// Only assert no panic and clean Teardown.
	_ = svc.Init(ctx)
	if err := svc.Teardown(); err != nil {
		t.Errorf("Teardown: %v", err)
	}
}

func TestMCPService_Teardown_NilSafe(t *testing.T) {
	svc := &MCPService{baseService: baseService{
		info: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "x"},
	}}
	if err := svc.Teardown(); err != nil {
		t.Fatalf("Teardown on uninitialised MCPService: %v", err)
	}
}
