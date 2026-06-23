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

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCPService extends baseService to handle MCP protocol proxying.
type MCPService struct {
	baseService
}

// Init initializes the base service.
func (m *MCPService) Init(ctx context.Context) error {
	return m.baseService.Init(ctx)
}

// Teardown chains to baseService.Teardown.
func (m *MCPService) Teardown() error {
	return m.baseService.Teardown()
}

// HandleStreamPassThrough connects to the backend and proxies JSON-RPC messages.
func (m *MCPService) HandleStreamPassThrough(s network.Stream) {
	defer func() {
		if err := s.Close(); err != nil {
			logger.Debugf("[MCPService] Failed to close MCP stream: %v", err)
		}
	}()

	var backendTransport mcp.Transport
	var closeTransport func()

	switch x := m.backend.(type) {
	case *api.RegisterServiceRequest_TargetUrl:
		backendTransport = &mcp.StreamableClientTransport{Endpoint: x.TargetUrl}
		closeTransport = func() {} // ClientTransport Close is handled by Connect's returned Connection
	case *api.RegisterServiceRequest_Command:
		bridge, ok := m.handler.(*StdioBridge)
		if !ok {
			logger.Errorf("[MCPService] %s: expected *StdioBridge handler for command-backed MCP service, got %T", m.info.Name, m.handler)
			return
		}
		backendTransport = newBridgeTransport(bridge)
		closeTransport = func() {} // Do not close the shared bridge
	default:
		logger.Errorf("[MCPService] %s: unsupported backend type %T", m.info.Name, m.backend)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer func() {
		if closeTransport != nil {
			closeTransport()
		}
	}()

	backendConn, err := backendTransport.Connect(ctx)
	if err != nil {
		logger.Errorf("[MCPService] %s: failed to connect to backend: %v", m.info.Name, err)
		return
	}
	defer func() { _ = backendConn.Close() }()

	clientTransport := NewStreamTransport(s)
	clientConn, err := clientTransport.Connect(ctx)
	if err != nil {
		logger.Errorf("[MCPService] %s: failed to connect to client: %v", m.info.Name, err)
		return
	}

	// Dumb pipe: Proxy JSON-RPC messages between client and backend
	errc := make(chan error, 2)

	go func() {
		for {
			msg, err := clientConn.Read(ctx)
			if err != nil {
				errc <- err
				return
			}
			if err := backendConn.Write(ctx, msg); err != nil {
				errc <- err
				return
			}
		}
	}()

	go func() {
		for {
			msg, err := backendConn.Read(ctx)
			if err != nil {
				errc <- err
				return
			}
			if err := clientConn.Write(ctx, msg); err != nil {
				errc <- err
				return
			}
		}
	}()

	<-errc
}
