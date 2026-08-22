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
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// How many agents a node is actually serving is the one number a mesh of
// agents cannot be described without, and until now nothing counted it. A node
// knew how many peers it had, which is a statement about hosts, not about the
// principals running on them.
//
// It is a count and not a label. Putting the agent identifier on a metric
// would be the obvious way to answer the same question, and it would put a
// thousand label values on a thousand series the first time anyone ran this at
// the scale it is for.

// maxTrackedAgents bounds the set behind the gauge. The identifiers come from
// the local gateway, which is trusted, so this is not defending against an
// attacker so much as against a bug: a gateway generating a fresh identity per
// request would otherwise grow this map until the node died, and a memory leak
// in the thing measuring the experiment is a bad way to end one.
const maxTrackedAgents = 100_000

var (
	agentsSeen = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sam_node_agents_seen",
			Help: "Distinct agents this node has served for a local gateway",
		},
	)

	agentsUntrackedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "sam_node_agents_untracked_total",
			Help: "Agent claims not counted because the tracking limit was reached",
		},
	)
)

var seenAgents = struct {
	sync.Mutex
	ids map[string]struct{}
}{ids: make(map[string]struct{})}

// recordAgentSeen counts an agent the first time this node serves it.
func recordAgentSeen(agentID string) {
	if agentID == "" {
		return
	}

	seenAgents.Lock()
	defer seenAgents.Unlock()

	if _, known := seenAgents.ids[agentID]; known {
		return
	}
	if len(seenAgents.ids) >= maxTrackedAgents {
		// Counted rather than silently dropped: a gauge that stops moving
		// looks like a mesh that stopped growing.
		agentsUntrackedTotal.Inc()
		return
	}

	seenAgents.ids[agentID] = struct{}{}
	agentsSeen.Set(float64(len(seenAgents.ids)))
}
