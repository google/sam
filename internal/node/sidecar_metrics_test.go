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
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClassifyRouteIsAClosedVocabulary(t *testing.T) {
	// A route label must not vary with anything an off-node caller chooses,
	// or a peer could grow this node's metric space by inventing names.
	cases := map[string]string{
		"/healthz":                       "health",
		"/metrics":                       "health",
		"/sam/service/discover":          "service-registry",
		"/sam/service/register":          "service-registry",
		"/sam/12D3KooWpeer/mcp/calc/run": "egress",
		"/v1/models":                     "models",
		"/v1/chat/completions":           "completions",
		"/v1/completions":                "completions",
		"/":                              "mcp",
		"/mcp":                           "mcp",
	}
	for path, want := range cases {
		if got := classifyRoute(path); got != want {
			t.Errorf("classifyRoute(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestObserveRequestsKeepsStreamingUsable(t *testing.T) {
	// The wrapper sits in front of MCP sessions and completions, both of which
	// stream. If it hides Flusher, a stream buffers until the handler returns
	// and every streaming consumer silently breaks.
	var (
		sawFlusher    bool
		sawController bool
	)
	handler := observeRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawFlusher = w.(http.Flusher)
		if err := http.NewResponseController(w).Flush(); err == nil {
			sawController = true
		}
		_, _ = w.Write([]byte("chunk"))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil))

	if !sawFlusher {
		t.Error("handler could not type-assert http.Flusher through the wrapper")
	}
	if !sawController {
		t.Error("http.ResponseController could not reach the underlying writer")
	}
	if got := rec.Body.String(); got != "chunk" {
		t.Errorf("body = %q, want %q", got, "chunk")
	}
}

func TestObserveRequestsRecordsTheHandlerStatus(t *testing.T) {
	handler := observeRequests(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/models", nil))

	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
}

func TestTimedWriterReportsOKWhenTheHandlerNeverSetAStatus(t *testing.T) {
	w := &timedWriter{ResponseWriter: httptest.NewRecorder(), route: "mcp"}
	if got := w.status(); got != http.StatusOK {
		t.Errorf("status = %d, want %d", got, http.StatusOK)
	}
}
