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
	"strings"

	"github.com/google/sam/api"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCPService extends baseService with an MCP ClientSession used to aggregate
// the backend's tools at Init time. Other parts of the codebase reach the
// tool list via type assertion (svc.(*MCPService)).
type MCPService struct {
	baseService
	session         *mcp.ClientSession
	aggregatedTools []*mcp.Tool
}

// Init builds the ingress handler via baseService.Init, then opens an MCP
// session over the appropriate native transport (StreamableClient for URL,
// bridgeTransport for stdio). ListTools is best-effort: failures are logged
// and the service still registers.
func (m *MCPService) Init(ctx context.Context) error {
	if err := m.baseService.Init(ctx); err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			_ = m.baseService.Teardown()
		}
	}()

	var transport mcp.Transport
	switch x := m.backend.(type) {
	case *api.RegisterServiceRequest_TargetUrl:
		// TODO: Consider routing URL-backed MCP ingress through the session
		// (as the stdio path effectively does via the bridge) so we can
		// decode/inspect MCP payloads and add per-tool-call observability
		// or policy enforcement at this boundary.
		transport = &mcp.StreamableClientTransport{Endpoint: x.TargetUrl}
	case *api.RegisterServiceRequest_Command:
		bridge, ok := m.handler.(*StdioBridge)
		if !ok {
			return fmt.Errorf("expected *StdioBridge handler for command-backed MCP service, got %T", m.handler)
		}
		transport = newBridgeTransport(bridge)
	default:
		return fmt.Errorf("unsupported backend type %T", m.backend)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "sam-node-aggregator", Version: "0.1.0"}, nil)
	s, err := client.Connect(ctx, transport, nil)
	if err != nil {
		// Best-effort: backend may not speak MCP (e.g. a plain HTTP service,
		// or `cat` used as a stdio echo). Ingress proxy still works.
		logger.Warnf("[MCPService] %s: mcp connect failed, registering without tool aggregation: %v", m.info.Name, err)
		success = true
		return nil
	}
	m.session = s

	res, err := s.ListTools(ctx, nil)
	if err != nil {
		logger.Warnf("[MCPService] %s: tools/list failed: %v", m.info.Name, err)
		success = true
		return nil
	}
	aggregated := make([]*mcp.Tool, 0, len(res.Tools))
	for _, tool := range res.Tools {
		namespaced := *tool
		namespaced.Name = fmt.Sprintf("%s.%s", m.info.Name, tool.Name)
		aggregated = append(aggregated, &namespaced)
	}
	m.aggregatedTools = aggregated

	success = true
	return nil
}

// Teardown closes the MCP session and chains to baseService.Teardown.
func (m *MCPService) Teardown() error {
	if m.session != nil {
		_ = m.session.Close()
		m.session = nil
	}
	m.aggregatedTools = nil
	return m.baseService.Teardown()
}

// Tools returns the namespaced aggregated tool list.
func (m *MCPService) Tools() []*mcp.Tool { return m.aggregatedTools }

// RegisterAggregatedTools adds this service's aggregated tools to the given
// MCP server. Each tool's invocation is forwarded to the underlying session
// with the service-name prefix stripped. No-op if aggregation produced
// nothing (e.g. ListTools failed at Init time).
func (m *MCPService) RegisterAggregatedTools(server *mcp.Server) {
	if m.session == nil {
		return
	}
	sess := m.session
	for _, tool := range m.aggregatedTools {
		toolCopy := tool
		parts := strings.SplitN(toolCopy.Name, ".", 2)
		if len(parts) != 2 {
			continue
		}
		originalName := parts[1]
		server.AddTool(toolCopy, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return sess.CallTool(ctx, &mcp.CallToolParams{
				Name:      originalName,
				Arguments: req.Params.Arguments,
			})
		})
	}
}
