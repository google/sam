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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	inferenceTokensTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sam_node_inference_tokens_total",
			Help: "Total number of inference tokens tracked by sam-node",
		},
		[]string{"peer_id", "model", "token_type"},
	)
)

// recordTokens increments the prompt and completion token metrics.
func recordTokens(peerID, model string, promptTokens, completionTokens int) {
	if model == "" {
		model = "unknown"
	}
	if peerID == "" {
		peerID = "unknown"
	}
	if promptTokens > 0 {
		inferenceTokensTotal.WithLabelValues(peerID, model, "prompt").Add(float64(promptTokens))
	}
	if completionTokens > 0 {
		inferenceTokensTotal.WithLabelValues(peerID, model, "completion").Add(float64(completionTokens))
	}
}
