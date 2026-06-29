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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/catalog"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
)

// serviceTypeByShortName maps the short string used in query params to ServiceType.
var serviceTypeByShortName = map[string]api.ServiceType{
	"mcp":       api.ServiceType_SERVICE_TYPE_MCP,
	"inference": api.ServiceType_SERVICE_TYPE_INFERENCE,
	"catalog":   api.ServiceType_SERVICE_TYPE_CATALOG,
}

// QueryCatalogParams defines parameters for the query_catalog tool.
type QueryCatalogParams struct {
	Type string `json:"type,omitempty"`
	Name string `json:"name,omitempty"`
}

// handleQueryCatalog implements the query_catalog MCP tool.
func handleQueryCatalog(store *catalog.Store) func(context.Context, *mcp.CallToolRequest, QueryCatalogParams) (*mcp.CallToolResult, any, error) {
	return func(_ context.Context, _ *mcp.CallToolRequest, params QueryCatalogParams) (*mcp.CallToolResult, any, error) {
		typeFilter := api.ServiceType_SERVICE_TYPE_UNSPECIFIED
		if params.Type != "" {
			t, ok := serviceTypeByShortName[strings.ToLower(params.Type)]
			if !ok {
				return nil, nil, fmt.Errorf("unknown service type: %s", params.Type)
			}
			typeFilter = t
		}
		entries := store.List(typeFilter, params.Name)
		data, err := json.Marshal(entries)
		if err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
		}, nil, nil
	}
}

// newCatalogMCPHandler returns an HTTP handler exposing the query_catalog MCP tool over SSE.
func newCatalogMCPHandler(store *catalog.Store) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "sam-catalog-mcp",
		Version: "0.1.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "query_catalog",
		Description: "Query the service catalog. Filter by type (mcp/inference/catalog) and/or name.",
	}, handleQueryCatalog(store))

	sseHandler := mcp.NewSSEHandler(func(_ *http.Request) *mcp.Server {
		return server
	}, nil)

	mux := http.NewServeMux()
	mux.Handle("/mcp/events", sseHandler)
	mux.Handle("/mcp/message", sseHandler)
	return mux
}

// registerSelf POSTs a SERVICE_TYPE_CATALOG registration to the sam-node sidecar.
func registerSelf(ctx context.Context, nodeBaseURL, token, ownMCPURL string) error {
	reqProto := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{
			Type:        api.ServiceType_SERVICE_TYPE_CATALOG,
			Name:        "catalog",
			Description: "service catalog",
		},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: ownMCPURL},
	}
	body, err := protojson.Marshal(reqProto)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nodeBaseURL+"/sam/service/register", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("register failed: %s %s", resp.Status, respBody)
	}
	return nil
}
