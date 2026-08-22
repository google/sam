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
	"strconv"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func resetSeenAgents() {
	seenAgents.Lock()
	defer seenAgents.Unlock()
	seenAgents.ids = make(map[string]struct{})
	agentsSeen.Set(0)
}

func TestAgentsSeenCountsEachAgentOnce(t *testing.T) {
	// The gauge answers "how many agents is this node serving". Counting a
	// busy agent repeatedly would answer "how many requests arrived", which
	// is a different question that other metrics already answer.
	resetSeenAgents()

	for range 5 {
		recordAgentSeen("reviewer-7.prod.acme.example")
	}
	recordAgentSeen("planner-2.prod.acme.example")

	if got := gaugeValue(t, agentsSeen); got != 2 {
		t.Errorf("agents seen = %v, want 2", got)
	}
}

func TestAgentsSeenIgnoresAnAbsentClaim(t *testing.T) {
	// Unattributed requests are normal: a node's own housekeeping carries no
	// agent. Counting the empty string would invent an agent that never ran.
	resetSeenAgents()

	recordAgentSeen("")

	if got := gaugeValue(t, agentsSeen); got != 0 {
		t.Errorf("agents seen = %v, want 0", got)
	}
}

func TestAgentsSeenStopsGrowingAtTheLimit(t *testing.T) {
	// A gateway minting a fresh identity per request would otherwise grow this
	// map until the node died, which is a poor way for an experiment to end.
	resetSeenAgents()

	seenAgents.Lock()
	for i := range maxTrackedAgents {
		seenAgents.ids[strconv.Itoa(i)] = struct{}{}
	}
	seenAgents.Unlock()

	before := counterValue(t, agentsUntrackedTotal)
	recordAgentSeen("one-too-many.prod.acme.example")

	if got := counterValue(t, agentsUntrackedTotal); got != before+1 {
		t.Errorf("untracked total = %v, want %v: the limit was hit silently", got, before+1)
	}

	seenAgents.Lock()
	overLimit := len(seenAgents.ids) > maxTrackedAgents
	seenAgents.Unlock()
	if overLimit {
		t.Error("the tracking set grew past its limit")
	}

	resetSeenAgents()
}

func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatalf("read gauge: %v", err)
	}
	return m.GetGauge().GetValue()
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}
