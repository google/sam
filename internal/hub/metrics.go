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

package hub

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	samHubEnrollmentTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sam_hub_enrollment_total",
		Help: "Total enrollment requests, partitioned by status.",
	}, []string{"status"})

	samHubMeshEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sam_hub_mesh_events_total",
		Help: "Total gossip events processed, partitioned by event_type.",
	}, []string{"event_type"})

	samHubKeyRotationsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sam_hub_key_rotations_total",
		Help: "The number of times the Hub has rotated its cryptographic keys.",
	})
)
