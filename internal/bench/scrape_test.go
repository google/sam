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

package bench

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseExpositionReadsLabelledSamples(t *testing.T) {
	// The numbers a report quotes come out of this parser, so it has to be
	// right about the cases the real endpoints actually emit.
	const exposition = `# HELP sam_box_flows_total Flows a sandbox asked to open
# TYPE sam_box_flows_total counter
sam_box_flows_total{route="mesh-service",outcome="allowed"} 42
sam_box_flows_total{route="unresolved",outcome="denied"} 7
process_resident_memory_bytes 1.8874368e+07
sam_box_flow_setup_seconds_bucket{route="mesh-service",le="0.001"} 12
`

	series, err := parseExposition(strings.NewReader(exposition))
	if err != nil {
		t.Fatalf("parseExposition: %v", err)
	}
	snap := &Snapshot{Series: series}

	if got, ok := snap.Value("sam_box_flows_total", map[string]string{"outcome": "denied"}); !ok || got != 7 {
		t.Errorf("denied flows = %v (found %v), want 7", got, ok)
	}
	if got := snap.Sum("sam_box_flows_total"); got != 49 {
		t.Errorf("total flows = %v, want 49", got)
	}
	if got, ok := snap.Value("process_resident_memory_bytes", nil); !ok || got != 18874368 {
		t.Errorf("rss = %v (found %v), want 18874368", got, ok)
	}
	if got, ok := snap.Value("sam_box_flow_setup_seconds_bucket", map[string]string{"le": "0.001"}); !ok || got != 12 {
		t.Errorf("bucket = %v (found %v), want 12", got, ok)
	}
}

func TestValueDistinguishesAbsentFromZero(t *testing.T) {
	// A counter that was never incremented is not exported at all. Reporting
	// it as zero would turn "this never happened" into "this happened zero
	// times", and only one of those is evidence.
	snap := &Snapshot{Series: []Series{{Name: "present", Value: 0}}}

	if _, ok := snap.Value("present", nil); !ok {
		t.Error("an exported zero was reported as absent")
	}
	if _, ok := snap.Value("absent", nil); ok {
		t.Error("a series that was never exported was reported as present")
	}
}

func TestParseExpositionKeepsCommasInsideLabelValues(t *testing.T) {
	// Error reasons and model names can contain commas. Splitting naively
	// would silently corrupt the label set rather than fail loudly.
	series, err := parseExposition(strings.NewReader(`m{a="x,y",b="z"} 1` + "\n"))
	if err != nil {
		t.Fatalf("parseExposition: %v", err)
	}
	if len(series) != 1 {
		t.Fatalf("got %d series, want 1", len(series))
	}
	if got := series[0].Labels["a"]; got != "x,y" {
		t.Errorf("label a = %q, want %q", got, "x,y")
	}
	if got := series[0].Labels["b"]; got != "z" {
		t.Errorf("label b = %q, want %q", got, "z")
	}
}

func TestScrapeReadsALiveEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("sam_node_requests_in_flight 3\n"))
	}))
	defer server.Close()

	snap, err := Scrape(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	if got, ok := snap.Value("sam_node_requests_in_flight", nil); !ok || got != 3 {
		t.Errorf("in flight = %v (found %v), want 3", got, ok)
	}
}

func TestScrapeReportsAnUnreachableEndpoint(t *testing.T) {
	// A silently empty snapshot would show up in a report as a process that
	// used no memory and served no requests.
	if _, err := Scrape(context.Background(), "http://127.0.0.1:1/metrics"); err == nil {
		t.Error("Scrape of an unreachable endpoint returned no error")
	}
}
