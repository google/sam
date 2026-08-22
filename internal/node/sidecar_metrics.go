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
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Half of what the sidecar serves streams: an MCP session and a completion
// both hold the response open for as long as the work lasts. Total handler
// time therefore measures the workload, not the mesh. Time to first byte is
// the number that reflects what the mesh added, so both are recorded and the
// distinction is kept in the metric names rather than left to the reader.

var requestBuckets = []float64{
	0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
}

var (
	requestTTFBSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sam_node_request_ttfb_seconds",
			Help:    "Time from accepting a sidecar request to its first response byte",
			Buckets: requestBuckets,
		},
		[]string{"route"},
	)

	requestDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sam_node_request_duration_seconds",
			Help:    "Time a sidecar request occupied its handler, including streaming",
			Buckets: requestBuckets,
		},
		[]string{"route", "code"},
	)

	requestsInFlight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sam_node_requests_in_flight",
			Help: "Sidecar requests currently being served",
		},
	)
)

// classifyRoute reduces a path to a closed vocabulary. Paths carry peer ids and
// service names chosen off-node, so the raw path can never become a label.
func classifyRoute(path string) string {
	switch {
	case path == "/healthz", path == "/readyz", path == "/metrics":
		return "health"
	case strings.HasPrefix(path, "/sam/service/"):
		return "service-registry"
	case strings.HasPrefix(path, "/sam/"):
		return "egress"
	case path == "/v1/models":
		return "models"
	case path == "/v1/chat/completions", path == "/v1/completions":
		return "completions"
	default:
		return "mcp"
	}
}

// observeRequests times every sidecar request. It wraps the whole mux so a
// route added later is measured without anyone remembering to instrument it.
func observeRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := classifyRoute(r.URL.Path)
		if route == "health" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		requestsInFlight.Inc()
		defer requestsInFlight.Dec()

		rec := &timedWriter{ResponseWriter: w, route: route, start: start}
		next.ServeHTTP(rec, r)

		requestDurationSeconds.WithLabelValues(route, strconv.Itoa(rec.status())).Observe(time.Since(start).Seconds())
	})
}

// timedWriter records when the first byte reached the client. It deliberately
// implements no optional interface itself: Unwrap lets http.ResponseController
// reach the real writer, so flushing and hijacking keep working for streams.
type timedWriter struct {
	http.ResponseWriter
	route  string
	start  time.Time
	code   int
	ttfbOK bool
}

func (t *timedWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

func (t *timedWriter) status() int {
	if t.code == 0 {
		return http.StatusOK
	}
	return t.code
}

func (t *timedWriter) observeTTFB() {
	if !t.ttfbOK {
		t.ttfbOK = true
		requestTTFBSeconds.WithLabelValues(t.route).Observe(time.Since(t.start).Seconds())
	}
}

func (t *timedWriter) WriteHeader(code int) {
	if t.code == 0 {
		t.code = code
	}
	t.observeTTFB()
	t.ResponseWriter.WriteHeader(code)
}

func (t *timedWriter) Write(b []byte) (int, error) {
	t.observeTTFB()
	return t.ResponseWriter.Write(b)
}

// Flush is kept because a streaming handler that type-asserts http.Flusher
// directly, rather than going through http.ResponseController, would otherwise
// stop finding one and buffer the whole stream.
func (t *timedWriter) Flush() {
	t.observeTTFB()
	if f, ok := t.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
