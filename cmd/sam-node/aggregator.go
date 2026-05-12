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
	"fmt"
	"net/http/httptest"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// aggregateServiceTools opens a persistent MCP client session to the
// service's HTTP handler via an in-process loopback server, calls
// tools/list, and populates manifest.AggregatedTools with namespaced
// copies of every returned tool.
//
// Best-effort: any failure leaves manifest fields nil/empty and returns
// nil so RegisterService is not aborted. The service remains reachable
// via the existing libp2p-HTTP proxy regardless.
func (n *SamNode) aggregateServiceTools(ctx context.Context, manifest *ServiceManifest) error {
	if manifest == nil || manifest.Info == nil || manifest.Handler == nil {
		return nil
	}
	serviceName := manifest.Info.Name

	loopback := httptest.NewServer(manifest.Handler)
	client := mcp.NewClient(&mcp.Implementation{Name: "sam-node-aggregator", Version: "0.1.0"}, nil)
	// Registered MCP backends are expected to speak streamable-http (the
	// current MCP transport). Path matches FastMCP's default mount point.
	transport := &mcp.StreamableClientTransport{Endpoint: loopback.URL + "/mcp/"}

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		logger.Warnf("[Aggregator] %s: connect to %s failed: %v", serviceName, loopback.URL, err)
		loopback.Close()
		return nil
	}

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		logger.Warnf("[Aggregator] %s: tools/list failed: %v", serviceName, err)
		// Keep session + loopback so detach cleans them up.
		manifest.MCPSession = session
		manifest.loopbackServer = loopback
		return nil
	}

	aggregated := make([]*mcp.Tool, 0, len(res.Tools))
	for _, tool := range res.Tools {
		namespaced := *tool
		namespaced.Name = fmt.Sprintf("%s.%s", serviceName, tool.Name)
		aggregated = append(aggregated, &namespaced)
	}

	manifest.MCPSession = session
	manifest.AggregatedTools = aggregated
	manifest.loopbackServer = loopback

	logger.Infof("[Aggregator] %s: aggregated %d tools", serviceName, len(aggregated))
	return nil
}

// detachServiceTools closes the long-lived aggregation state on a
// manifest. It is safe to call on nil, on a partially-initialised
// manifest, and repeatedly on the same manifest.
//
// detach does NOT remove aggregated tool registrations from any
// *mcp.Server; the per-stream peer-facing server is rebuilt on the
// next inbound stream and will simply not find this manifest in
// n.services (assuming the caller has already removed it).
func (n *SamNode) detachServiceTools(manifest *ServiceManifest) {
	if manifest == nil {
		return
	}
	if manifest.MCPSession != nil {
		if err := manifest.MCPSession.Close(); err != nil {
			logger.Warnf("[Aggregator] detach: close session: %v", err)
		}
		manifest.MCPSession = nil
	}
	if manifest.loopbackServer != nil {
		manifest.loopbackServer.Close()
		manifest.loopbackServer = nil
	}
	manifest.AggregatedTools = nil
}
