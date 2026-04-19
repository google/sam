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

package protocol

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"sam/pkg/economy"
	"sam/pkg/identity"
)

type testObserver struct {
	mu           sync.Mutex
	successCount int
	failureCount int
	lastPeerID   string
	lastFailure  string
}

func (o *testObserver) OnSuccess(peerID string, _ time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.successCount++
	o.lastPeerID = peerID
}

func (o *testObserver) OnFailure(peerID string, errorType string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.failureCount++
	o.lastPeerID = peerID
	o.lastFailure = errorType
}

func (o *testObserver) GetCounts() (success, failure int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.successCount, o.failureCount
}

func (o *testObserver) GetLastFailure() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lastFailure
}

type staticResponseConnector struct{}

func (staticResponseConnector) Open(context.Context) (mcp.Transport, error) {
	return staticResponseTransport{}, nil
}

type staticResponseTransport struct{}

func (staticResponseTransport) Connect(context.Context) (mcp.Connection, error) {
	msg, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","id":"sam-call","result":{"ok":true}}`))
	if err != nil {
		return nil, err
	}
	return &staticResponseConn{response: msg}, nil
}

type staticResponseConn struct {
	response jsonrpc.Message
}

func (c *staticResponseConn) Read(context.Context) (jsonrpc.Message, error) {
	return c.response, nil
}

func (c *staticResponseConn) Write(context.Context, jsonrpc.Message) error {
	return nil
}

func (c *staticResponseConn) Close() error {
	return nil
}

func (c *staticResponseConn) SessionID() string {
	return "test-session"
}

func TestExecuteSuccessRecordsObserver(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New(server) error = %v", err)
	}
	defer func() { _ = serverHost.Close() }()

	clientHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New(client) error = %v", err)
	}
	defer func() { _ = clientHost.Close() }()

	serverObserver := &testObserver{}
	svc, err := NewA2AService(serverHost, staticResponseConnector{}, serverObserver)
	if err != nil {
		t.Fatalf("NewA2AService(server) error = %v", err)
	}
	defer svc.Close()

	clientObserver := &testObserver{}
	resp, err := Execute(ctx, clientHost, ExecuteRequest{
		Target: peer.AddrInfo{ID: serverHost.ID(), Addrs: serverHost.Addrs()},
		Vouch: identity.NewVouch(
			clientHost.ID().String(),
			"self",
			"sub",
			map[string]string{"name": "tester"},
			time.Hour,
		),
		Biscuit:    "test-biscuit",
		Payment:    economy.Micropayment{Amount: 1, Asset: "sam-credit", Nonce: "n-1"},
		MCPRequest: []byte(`{"jsonrpc":"2.0","id":"sam-call","method":"message","params":{"message":"ping"}}`),
	}, clientObserver)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(resp) == 0 {
		t.Fatalf("response is empty")
	}
	if success, failure := clientObserver.GetCounts(); success != 1 || failure != 0 {
		t.Fatalf("client observer counts = success:%d failure:%d, want success:1 failure:0", success, failure)
	}
	if success, failure := serverObserver.GetCounts(); success != 1 || failure != 0 {
		t.Fatalf("server observer counts = success:%d failure:%d, want success:1 failure:0", success, failure)
	}
}

func TestExecuteReturnsLivenessErrorWhenPeerDown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New(server) error = %v", err)
	}

	clientHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New(client) error = %v", err)
	}
	defer func() { _ = clientHost.Close() }()

	target := peer.AddrInfo{ID: serverHost.ID(), Addrs: serverHost.Addrs()}
	if err := serverHost.Close(); err != nil {
		t.Fatalf("serverHost.Close() error = %v", err)
	}

	clientObserver := &testObserver{}
	_, err = Execute(ctx, clientHost, ExecuteRequest{
		Target:     target,
		Biscuit:    "test-biscuit",
		Payment:    economy.Micropayment{Amount: 1, Asset: "sam-credit", Nonce: "n-2"},
		MCPRequest: []byte(`{"jsonrpc":"2.0","id":"sam-call","method":"message","params":{"message":"ping"}}`),
	}, clientObserver)
	if err == nil {
		t.Fatalf("Execute() error = nil, want liveness error")
	}
	var liveErr *LivenessError
	if !errors.As(err, &liveErr) {
		t.Fatalf("Execute() error = %v, want LivenessError", err)
	}
	if clientObserver.failureCount == 0 {
		t.Fatalf("expected failure hook to be called")
	}
	if clientObserver.lastFailure != FailureTypeLiveness {
		t.Fatalf("failure type = %q, want %q", clientObserver.lastFailure, FailureTypeLiveness)
	}
}
