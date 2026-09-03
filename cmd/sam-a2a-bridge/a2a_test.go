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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeSidecar records the last JSON-RPC request and returns a canned result.
func fakeSidecar(t *testing.T, wantPath string, result string, capture *map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, wantPath) {
			t.Errorf("request path = %q, want prefix %q", r.URL.Path, wantPath)
		}
		body, _ := io.ReadAll(r.Body)
		var rpc map[string]any
		_ = json.Unmarshal(body, &rpc)
		if capture != nil {
			*capture = rpc
		}
		w.Header().Set("Content-Type", "application/json")
		id, _ := json.Marshal(rpc["id"])
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(id) + `,"result":` + result + `}`))
	}))
}

// SendMessage results arrive enveloped as {"task":...}/{"message":...} per
// a2a.StreamResponse; GetTask results don't (unmarshaled directly into a2a.Task).

func TestSendAgentTaskMapsTaskResult(t *testing.T) {
	var rpc map[string]any
	task := `{"task":{"kind":"task","id":"t1","contextId":"c1",` +
		`"status":{"state":"working","message":{"kind":"message","messageId":"m1","role":"agent",` +
		`"parts":[{"kind":"text","text":"thinking"}]}}}}`
	srv := fakeSidecar(t, "/sam/12D3KooWpeer/a2a/echo", task, &rpc)
	defer srv.Close()

	cfg := bridgeConfig{sidecarURL: srv.URL, token: "tok"}
	got, err := sendAgentTask(context.Background(), cfg, sendAgentTaskParams{
		Peer: "12D3KooWpeer", Service: "echo", Message: "hi",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.TaskID != "t1" || got.ContextID != "c1" {
		t.Errorf("ids = %q/%q, want t1/c1", got.TaskID, got.ContextID)
	}
	if !strings.Contains(strings.ToLower(got.State), "working") {
		t.Errorf("state = %q, want it to convey 'working'", got.State)
	}
	if got.Text != "thinking" {
		t.Errorf("text = %q, want %q", got.Text, "thinking")
	}
	// a2a-go v2.5.0 sends the JSON-RPC method as "SendMessage" (internal/jsonrpc.MethodMessageSend),
	// not the wire-spec "message/send".
	if m, _ := rpc["method"].(string); m != "SendMessage" {
		t.Errorf("jsonrpc method = %q, want SendMessage", m)
	}
}

func TestSendAgentTaskMapsMessageResult(t *testing.T) {
	msg := `{"message":{"kind":"message","messageId":"m2","role":"agent","taskId":"t2","contextId":"c2",` +
		`"parts":[{"kind":"text","text":"4"}]}}`
	srv := fakeSidecar(t, "/sam/12D3KooWpeer/a2a/echo", msg, nil)
	defer srv.Close()

	got, err := sendAgentTask(context.Background(), bridgeConfig{sidecarURL: srv.URL},
		sendAgentTaskParams{Peer: "12D3KooWpeer", Service: "echo", Message: "2+2?"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != "4" || got.TaskID != "t2" || got.ContextID != "c2" {
		t.Errorf("got %+v", got)
	}
	if got.State != "completed" {
		t.Errorf("a direct Message reply is final; state = %q, want completed", got.State)
	}
}

func TestSendAgentTaskThreadsContinuationIDs(t *testing.T) {
	var rpc map[string]any
	task := `{"task":{"kind":"task","id":"t3","contextId":"c3","status":{"state":"completed"}}}`
	srv := fakeSidecar(t, "/sam/12D3KooWpeer/a2a/echo", task, &rpc)
	defer srv.Close()

	_, err := sendAgentTask(context.Background(), bridgeConfig{sidecarURL: srv.URL},
		sendAgentTaskParams{Peer: "12D3KooWpeer", Service: "echo", Message: "more",
			ContextID: "c3", TaskID: "t3"})
	if err != nil {
		t.Fatal(err)
	}
	params, _ := rpc["params"].(map[string]any)
	message, _ := params["message"].(map[string]any)
	if message["taskId"] != "t3" || message["contextId"] != "c3" {
		t.Errorf("continuation ids not threaded: %v", message)
	}
}

func TestSendAgentTaskSurfacesSidecarRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Required labels not attested by provider", http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := sendAgentTask(context.Background(), bridgeConfig{sidecarURL: srv.URL},
		sendAgentTaskParams{Peer: "12D3KooWpeer", Service: "echo", Message: "hi",
			RequiredLabels: "region=us-east-1"})
	if err == nil {
		t.Fatal("403 must surface as an error")
	}
	if !strings.Contains(err.Error(), "Required labels not attested by provider") {
		t.Errorf("refusal text lost: %v", err)
	}
}

func TestGetAgentTaskMapsResult(t *testing.T) {
	var rpc map[string]any
	task := `{"kind":"task","id":"t4","contextId":"c4","status":{"state":"completed"},` +
		`"artifacts":[{"artifactId":"a1","parts":[{"kind":"text","text":"final answer"}]}]}`
	srv := fakeSidecar(t, "/sam/12D3KooWpeer/a2a/echo", task, &rpc)
	defer srv.Close()

	got, err := getAgentTask(context.Background(), bridgeConfig{sidecarURL: srv.URL},
		getAgentTaskParams{Peer: "12D3KooWpeer", Service: "echo", TaskID: "t4"})
	if err != nil {
		t.Fatal(err)
	}
	// a2a-go v2.5.0 sends the JSON-RPC method as "GetTask" (internal/jsonrpc.MethodTasksGet),
	// not the wire-spec "tasks/get".
	if m, _ := rpc["method"].(string); m != "GetTask" {
		t.Errorf("jsonrpc method = %q, want GetTask", m)
	}
	if got.TaskID != "t4" || got.Text != "final answer" {
		t.Errorf("got %+v", got)
	}
	if !strings.Contains(strings.ToLower(got.State), "completed") {
		t.Errorf("state = %q, want it to convey 'completed'", got.State)
	}
}
