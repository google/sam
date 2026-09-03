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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func textContent(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("content items = %d, want 1", len(res.Content))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content type = %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

func TestHandleSendAgentTaskSuccess(t *testing.T) {
	// SendMessage results arrive enveloped as {"task":...} per a2a.StreamResponse (a2a_test.go).
	task := `{"task":{"kind":"task","id":"t1","contextId":"c1","status":{"state":"completed",` +
		`"message":{"kind":"message","messageId":"m1","role":"agent","parts":[{"kind":"text","text":"done"}]}}}}`
	srv := fakeSidecar(t, "/sam/12D3KooWpeer/a2a/echo", task, nil)
	defer srv.Close()

	res, _, err := handleSendAgentTask(bridgeConfig{sidecarURL: srv.URL})(
		context.Background(), nil, sendAgentTaskParams{Peer: "12D3KooWpeer", Service: "echo", Message: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", textContent(t, res))
	}
	var got taskResult
	if err := json.Unmarshal([]byte(textContent(t, res)), &got); err != nil {
		t.Fatalf("output is not the 4-field JSON: %v", err)
	}
	if got.TaskID != "t1" || got.Text != "done" {
		t.Errorf("got %+v", got)
	}
}

func TestHandleSendAgentTaskRefusalIsToolError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Required labels not attested by provider", http.StatusForbidden)
	}))
	defer srv.Close()

	res, _, err := handleSendAgentTask(bridgeConfig{sidecarURL: srv.URL})(
		context.Background(), nil, sendAgentTaskParams{Peer: "12D3KooWpeer", Service: "echo",
			Message: "hi", RequiredLabels: "region=us-east-1"})
	if err != nil {
		t.Fatalf("refusals are tool errors, not protocol errors: %v", err)
	}
	if !res.IsError {
		t.Fatal("IsError must be true on sidecar refusal")
	}
	text := textContent(t, res)
	if !strings.HasPrefix(text, "403: Required labels not attested by provider") {
		t.Errorf("refusal must lead with status + verbatim body, got %q", text)
	}
}

func TestHandleGetAgentTask(t *testing.T) {
	task := `{"kind":"task","id":"t9","contextId":"c9","status":{"state":"completed"},` +
		`"artifacts":[{"artifactId":"a1","parts":[{"kind":"text","text":"result"}]}]}`
	srv := fakeSidecar(t, "/sam/12D3KooWpeer/a2a/echo", task, nil)
	defer srv.Close()

	res, _, err := handleGetAgentTask(bridgeConfig{sidecarURL: srv.URL})(
		context.Background(), nil, getAgentTaskParams{Peer: "12D3KooWpeer", Service: "echo", TaskID: "t9"})
	if err != nil {
		t.Fatal(err)
	}
	var got taskResult
	if err := json.Unmarshal([]byte(textContent(t, res)), &got); err != nil {
		t.Fatal(err)
	}
	if got.TaskID != "t9" || got.Text != "result" {
		t.Errorf("got %+v", got)
	}
}
