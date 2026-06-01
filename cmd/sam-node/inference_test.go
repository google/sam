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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
	dto "github.com/prometheus/client_model/go"
)

func getCounterValue(peerID, model, tokenType string) float64 {
	metric, err := inferenceTokensTotal.GetMetricWithLabelValues(peerID, model, tokenType)
	if err != nil {
		return 0
	}
	var m dto.Metric
	if err := metric.Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

func TestInferenceService_TokenAccountability_JSON(t *testing.T) {
	peerID := "test-peer-json"
	modelName := "test-model-json"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{
			"model": "%s",
			"usage": {
				"prompt_tokens": 42,
				"completion_tokens": 99
			}
		}`, modelName)
	}))
	defer server.Close()

	svc := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: "test-inference-json"},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: server.URL},
		},
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	req := httptest.NewRequest("POST", "http://localhost/chat", bytes.NewReader([]byte(`{"test":true}`)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Peer-Id", peerID)
	w := httptest.NewRecorder()

	initialPromptTokens := getCounterValue(peerID, modelName, "prompt")
	initialCompletionTokens := getCounterValue(peerID, modelName, "completion")

	svc.Handler().ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d, body: %s", resp.StatusCode, string(body))
	}

	// Wait briefly for async recording goroutine to finish
	time.Sleep(50 * time.Millisecond)

	promptTokens := getCounterValue(peerID, modelName, "prompt") - initialPromptTokens
	completionTokens := getCounterValue(peerID, modelName, "completion") - initialCompletionTokens

	if promptTokens != 42 {
		t.Errorf("Expected 42 prompt tokens, got %f", promptTokens)
	}
	if completionTokens != 99 {
		t.Errorf("Expected 99 completion tokens, got %f", completionTokens)
	}
}

func TestInferenceService_TokenAccountability_SSE(t *testing.T) {
	peerID := "test-peer-sse"
	modelName := "test-model-sse"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		flusher, _ := w.(http.Flusher)

		_, _ = fmt.Fprintf(w, "data: {\"model\":\"%s\"}\n\n", modelName)
		flusher.Flush()

		_, _ = fmt.Fprintf(w, "data: {\"model\":\"%s\",\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":150}}\n\n", modelName)
		flusher.Flush()

		_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer server.Close()

	svc := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: "test-inference-sse"},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: server.URL},
		},
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	req := httptest.NewRequest("POST", "http://localhost/chat", bytes.NewReader([]byte(`{"test":true}`)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Peer-Id", peerID)
	w := httptest.NewRecorder()

	initialPromptTokens := getCounterValue(peerID, modelName, "prompt")
	initialCompletionTokens := getCounterValue(peerID, modelName, "completion")

	svc.Handler().ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d, body: %s", resp.StatusCode, string(body))
	}

	// Let's assert that we actually got the SSE stream
	if !strings.Contains(string(body), "[DONE]") {
		t.Fatalf("Expected body to contain [DONE], got: %q", string(body))
	}

	// Wait briefly for async recording goroutine to finish
	time.Sleep(50 * time.Millisecond)

	promptTokens := getCounterValue(peerID, modelName, "prompt") - initialPromptTokens
	completionTokens := getCounterValue(peerID, modelName, "completion") - initialCompletionTokens

	if promptTokens != 50 {
		t.Errorf("Expected 50 prompt tokens, got %f", promptTokens)
	}
	if completionTokens != 150 {
		t.Errorf("Expected 150 completion tokens, got %f", completionTokens)
	}
}
