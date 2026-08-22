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

package sambox

import (
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// The boundary is the one place that sees every flow an agent opens, so it is
// the only honest place to measure what the boundary costs and what it refused.
// Labels stay closed vocabularies: a destination name is agent-controlled, and
// putting it in a label would let a sandbox grow the metric space without bound.

// flowSetupBuckets resolve from a sidecar hop on a Unix socket (tens of
// microseconds) up to a mesh dial that crosses the DHT (seconds). The default
// buckets start at 5ms, which is above the median this measures.
var flowSetupBuckets = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

var (
	flowsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sam_box_flows_total",
			Help: "Flows a sandbox asked the boundary to open, by route class and outcome",
		},
		[]string{"route", "outcome"},
	)

	flowSetupSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sam_box_flow_setup_seconds",
			Help:    "Time from an admitted CONNECT to a usable destination connection",
			Buckets: flowSetupBuckets,
		},
		[]string{"route"},
	)

	flowsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sam_box_flows_active",
			Help: "Flows currently relaying through the boundary",
		},
	)
)

// routeUnresolved labels a flow the router refused before it could be
// classified, so a denial is never miscounted against a real route.
const routeUnresolved = "unresolved"

// outcomeFor maps a dial result onto the closed vocabulary the counters use.
func outcomeFor(err error) string {
	switch {
	case err == nil:
		return "allowed"
	case errors.Is(err, ErrNotAllowed):
		return "denied"
	case errors.Is(err, ErrHostUnreachable):
		return "unreachable"
	case errors.Is(err, ErrConnectionRefused):
		return "refused"
	default:
		return "error"
	}
}

// recordFlow accounts one attempt to open a destination. setup is only
// meaningful when the attempt succeeded, so it is only observed then.
func recordFlow(route string, setup time.Duration, err error) {
	flowsTotal.WithLabelValues(route, outcomeFor(err)).Inc()
	if err == nil {
		flowSetupSeconds.WithLabelValues(route).Observe(setup.Seconds())
	}
}
