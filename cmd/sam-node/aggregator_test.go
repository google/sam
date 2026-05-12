// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// newFakeMCPHandler returns an http.Handler that serves a tiny MCP server
// over streamable-http, registering the given tools. Matches the transport
// the aggregator uses against registered backends.
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

func TestAggregateServiceTools_HappyPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tools := []*mcp.Tool{
		{Name: "review_pr", Description: "Run a code review", InputSchema: map[string]any{"type": "object"}},
		{Name: "add_comment", Description: "Add a comment", InputSchema: map[string]any{"type": "object"}},
	}
	handler := newFakeMCPHandler(t, tools)

	node := &SamNode{services: map[string]*ServiceManifest{}}
	manifest := &ServiceManifest{
		Info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		Handler: handler,
	}

	if err := node.aggregateServiceTools(ctx, manifest); err != nil {
		t.Fatalf("aggregateServiceTools returned error: %v", err)
	}

	if manifest.MCPSession == nil {
		t.Fatal("MCPSession not populated")
	}
	if manifest.loopbackServer == nil {
		t.Fatal("loopbackServer not populated")
	}
	if got := len(manifest.AggregatedTools); got != 2 {
		t.Fatalf("AggregatedTools length: got %d, want 2", got)
	}

	gotNames := map[string]bool{}
	for _, tool := range manifest.AggregatedTools {
		gotNames[tool.Name] = true
		if tool.InputSchema == nil {
			t.Errorf("tool %q has nil InputSchema", tool.Name)
		}
	}
	for _, want := range []string{"code-reviewer.review_pr", "code-reviewer.add_comment"} {
		if !gotNames[want] {
			t.Errorf("expected aggregated tool name %q not found; got %v", want, gotNames)
		}
	}

	// Clean up so the test doesn't leak the loopback server / session.
	if manifest.MCPSession != nil {
		_ = manifest.MCPSession.Close()
	}
	if manifest.loopbackServer != nil {
		manifest.loopbackServer.Close()
	}
}

func TestAggregateServiceTools_NonMCPHandler_BestEffort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A handler that always 500s on any request — not a real MCP server.
	brokenHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	node := &SamNode{services: map[string]*ServiceManifest{}}
	manifest := &ServiceManifest{
		Info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "broken"},
		Handler: brokenHandler,
	}

	err := node.aggregateServiceTools(ctx, manifest)
	if err != nil {
		t.Fatalf("aggregateServiceTools returned error for broken handler: %v", err)
	}
	if len(manifest.AggregatedTools) != 0 {
		t.Fatalf("expected zero aggregated tools for broken handler, got %d", len(manifest.AggregatedTools))
	}

	// Cleanup any partially-initialised state.
	if manifest.MCPSession != nil {
		_ = manifest.MCPSession.Close()
	}
	if manifest.loopbackServer != nil {
		manifest.loopbackServer.Close()
	}
}

func TestAggregateServiceTools_NilManifest_NoOp(t *testing.T) {
	node := &SamNode{services: map[string]*ServiceManifest{}}
	if err := node.aggregateServiceTools(context.Background(), nil); err != nil {
		t.Fatalf("expected nil error for nil manifest, got %v", err)
	}
}

func TestDetachServiceTools_ClosesSessionAndLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tools := []*mcp.Tool{
		{Name: "ping", Description: "ping", InputSchema: map[string]any{"type": "object"}},
	}
	handler := newFakeMCPHandler(t, tools)

	node := &SamNode{services: map[string]*ServiceManifest{}}
	manifest := &ServiceManifest{
		Info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "svc"},
		Handler: handler,
	}
	if err := node.aggregateServiceTools(ctx, manifest); err != nil {
		t.Fatalf("aggregateServiceTools: %v", err)
	}
	loopbackURL := manifest.loopbackServer.URL

	node.detachServiceTools(manifest)

	// After detach: loopback server must no longer accept connections.
	resp, err := http.Get(loopbackURL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected GET to closed loopback server to fail, but it succeeded")
	}

	// detach must be safe to call again.
	node.detachServiceTools(manifest)
}

func TestDetachServiceTools_NilOrEmpty_NoOp(t *testing.T) {
	node := &SamNode{}
	node.detachServiceTools(nil)
	node.detachServiceTools(&ServiceManifest{})
}
