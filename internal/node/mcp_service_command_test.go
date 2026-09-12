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

package node

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// TestEchoHelperProcess is a subprocess entry point (self-re-exec, as
// node_test.go's TestStartRenewalLoop_ExpiredAndFails does), standing in
// for a command-backed MCP server. It echoes each JSON-RPC call's id back
// tagged with its own PID, so a test can tell which subprocess answered.
func TestEchoHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_ECHO_HELPER") != "1" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	w := bufio.NewWriter(os.Stdout)
	pid := os.Getpid()
	for scanner.Scan() {
		var msg map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			continue
		}
		id, ok := msg["id"]
		if !ok {
			continue // notification: no reply, per JSON-RPC
		}
		out, err := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"result":  map[string]any{"pid": pid},
		})
		if err != nil {
			continue
		}
		_, _ = w.Write(out)
		_ = w.WriteByte('\n')
		_ = w.Flush()
	}
	os.Exit(0)
}

func newEchoCommandMCPService(t *testing.T) *MCPService {
	t.Helper()
	return &MCPService{
		baseService: baseService{
			info: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "echo"},
			backend: &api.RegisterServiceRequest_Command{
				Command: &api.CommandBackend{
					Command: []string{os.Args[0], "-test.run=TestEchoHelperProcess"},
					Env:     map[string]string{"GO_WANT_ECHO_HELPER": "1"},
				},
			},
		},
	}
}

// Two calls, both sending id:1, must be answered by two different
// subprocesses - not one shared one, which is how session A used to be
// able to read session B's reply.
func TestMCPService_BackendTransport_CommandBackendUsesSeparateSubprocess(t *testing.T) {
	m := newEchoCommandMCPService(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	connectAndCallID1 := func() float64 {
		tr, err := m.backendTransport()
		if err != nil {
			t.Fatalf("backendTransport: %v", err)
		}
		conn, err := tr.Connect(ctx)
		if err != nil {
			t.Fatalf("Connect: %v", err)
		}
		defer func() { _ = conn.Close() }()

		jid, err := jsonrpc.MakeID(float64(1))
		if err != nil {
			t.Fatalf("MakeID: %v", err)
		}
		if err := conn.Write(ctx, &jsonrpc.Request{ID: jid, Method: "tools/call"}); err != nil {
			t.Fatalf("Write: %v", err)
		}
		msg, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		resp, ok := msg.(*jsonrpc.Response)
		if !ok {
			t.Fatalf("Read: got %T, want *jsonrpc.Response", msg)
		}
		var result map[string]any
		if err := json.Unmarshal(resp.Result, &result); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		pidVal, ok := result["pid"].(float64)
		if !ok {
			t.Fatalf("result has no numeric pid: %#v", result)
		}
		return pidVal
	}

	pidA := connectAndCallID1()
	pidB := connectAndCallID1()

	if pidA == pidB {
		t.Fatalf("both calls (each sending id:1) were answered by the same subprocess (pid %v) - backendTransport is sharing a process across calls again", pidA)
	}
}

// Same check under concurrency: two sessions running at once, each always
// sending id:1, must never see a reply that isn't theirs.
func TestMCPService_BackendTransport_ConcurrentCallsDoNotCrossTalk(t *testing.T) {
	m := newEchoCommandMCPService(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const rounds = 20
	var wg sync.WaitGroup
	errCh := make(chan error, rounds*2)

	session := func(tag string) {
		defer wg.Done()
		tr, err := m.backendTransport()
		if err != nil {
			errCh <- fmt.Errorf("%s: backendTransport: %w", tag, err)
			return
		}
		conn, err := tr.Connect(ctx)
		if err != nil {
			errCh <- fmt.Errorf("%s: Connect: %w", tag, err)
			return
		}
		defer func() { _ = conn.Close() }()

		myPID := -1.0
		for r := 0; r < rounds; r++ {
			jid, err := jsonrpc.MakeID(float64(1)) // every session starts its own ids at 1
			if err != nil {
				errCh <- fmt.Errorf("%s: MakeID: %w", tag, err)
				return
			}
			if err := conn.Write(ctx, &jsonrpc.Request{ID: jid, Method: "tools/call"}); err != nil {
				errCh <- fmt.Errorf("%s round %d: Write: %w", tag, r, err)
				return
			}
			msg, err := conn.Read(ctx)
			if err != nil {
				errCh <- fmt.Errorf("%s round %d: Read: %w", tag, r, err)
				return
			}
			resp, ok := msg.(*jsonrpc.Response)
			if !ok {
				errCh <- fmt.Errorf("%s round %d: got %T, want *jsonrpc.Response", tag, r, msg)
				return
			}
			var result map[string]any
			if err := json.Unmarshal(resp.Result, &result); err != nil {
				errCh <- fmt.Errorf("%s round %d: unmarshal result: %w", tag, r, err)
				return
			}
			pid, _ := result["pid"].(float64)
			if myPID == -1.0 {
				myPID = pid
			} else if pid != myPID {
				errCh <- fmt.Errorf("%s round %d: reply came from pid %v, previous rounds came from pid %v - cross-talk between sessions", tag, r, pid, myPID)
				return
			}
		}
	}

	wg.Add(2)
	go session("session-A")
	go session("session-B")
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}
