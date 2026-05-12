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
	"io"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// bridgeTransport adapts a StdioBridge to the mcp.Transport interface.
// Reads pull lines from a Subscribe channel; writes go through Send.
// Multiple bridgeTransports can coexist on one bridge; JSON-RPC IDs
// distinguish their responses, as with HTTP/SSE subscribers.
type bridgeTransport struct {
	bridge *StdioBridge
	ch     <-chan string
	unsub  func()
}

func newBridgeTransport(b *StdioBridge) *bridgeTransport {
	return &bridgeTransport{bridge: b}
}

func (t *bridgeTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	ch, unsub := t.bridge.Subscribe()
	t.ch = ch
	t.unsub = unsub
	return t, nil
}

func (t *bridgeTransport) Read(ctx context.Context) (jsonrpc.Message, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case line, ok := <-t.ch:
		if !ok {
			return nil, io.EOF
		}
		return jsonrpc.DecodeMessage([]byte(line))
	}
}

func (t *bridgeTransport) Write(ctx context.Context, msg jsonrpc.Message) error {
	data, err := jsonrpc.EncodeMessage(msg)
	if err != nil {
		return err
	}
	return t.bridge.Send(data)
}

func (t *bridgeTransport) Close() error {
	if t.unsub != nil {
		t.unsub()
		t.unsub = nil
	}
	return nil
}

func (t *bridgeTransport) SessionID() string { return "" }
