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
	"sync/atomic"
	"testing"
	"time"
)

func TestPercentileUsesNearestRank(t *testing.T) {
	// Every number this package reports rests on this function. Interpolating
	// percentiles would report a latency that was never observed, which is
	// exactly the kind of number a reader would take literally.
	sorted := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	cases := []struct {
		p    float64
		want float64
	}{
		{50, 5},
		{90, 9},
		{95, 10},
		{99, 10},
		{100, 10},
	}
	for _, tc := range cases {
		if got := percentile(sorted, tc.p); got != tc.want {
			t.Errorf("percentile(p%v) = %v, want %v", tc.p, got, tc.want)
		}
	}
}

func TestPercentileHandlesDegenerateInput(t *testing.T) {
	if got := percentile(nil, 50); got != 0 {
		t.Errorf("percentile of nothing = %v, want 0", got)
	}
	if got := percentile([]float64{42}, 99); got != 42 {
		t.Errorf("percentile of one sample = %v, want 42", got)
	}
}

func TestSummariseReportsTheShapeNotJustTheMean(t *testing.T) {
	// A mean alone cannot tell a steady mesh from one that stalls on one
	// request in twenty, and the tail is the whole point of the measurement.
	values := make([]time.Duration, 0, 100)
	for i := range 99 {
		_ = i
		values = append(values, time.Millisecond)
	}
	values = append(values, time.Second)

	d := summarise(values)
	if d.Count != 100 {
		t.Errorf("Count = %d, want 100", d.Count)
	}
	if d.P50 != 1 {
		t.Errorf("P50 = %v ms, want 1", d.P50)
	}
	if d.Max != 1000 {
		t.Errorf("Max = %v ms, want 1000", d.Max)
	}
	if d.StdDev <= 0 {
		t.Errorf("StdDev = %v, want a positive spread for a bimodal sample", d.StdDev)
	}
}

func TestSummariseOfNothingIsEmptyNotAPanic(t *testing.T) {
	if got := summarise(nil); got.Count != 0 {
		t.Errorf("Count = %d, want 0", got.Count)
	}
}

func TestRunIssuesExactlyTheRequestedLoad(t *testing.T) {
	// A load generator that quietly issues a different number of requests
	// than it reports would corrupt every throughput figure derived from it.
	var served atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	report, err := Run(context.Background(), Options{
		Target:      server.URL,
		Requests:    50,
		Warmup:      10,
		Concurrency: 5,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := served.Load(); got != 60 {
		t.Errorf("server saw %d requests, want 60 (50 measured + 10 warmup)", got)
	}
	if report.Succeeded != 50 {
		t.Errorf("Succeeded = %d, want 50", report.Succeeded)
	}
	if report.Failed != 0 {
		t.Errorf("Failed = %d, want 0: %v", report.Failed, report.Errors)
	}
	if report.WarmupTTFB == nil || report.WarmupTTFB.Count != 10 {
		t.Errorf("warmup was not reported separately: %+v", report.WarmupTTFB)
	}
	if report.TTFB.Count != 50 {
		t.Errorf("TTFB.Count = %d, want 50", report.TTFB.Count)
	}
}

func TestRunCountsErrorStatusesAsFailures(t *testing.T) {
	// A mesh that answers "denied" very quickly must never look like a mesh
	// that answers correctly very quickly.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	report, err := Run(context.Background(), Options{Target: server.URL, Requests: 5, Concurrency: 1})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if report.Succeeded != 0 {
		t.Errorf("Succeeded = %d, want 0", report.Succeeded)
	}
	if report.Failed != 5 {
		t.Errorf("Failed = %d, want 5", report.Failed)
	}
	if report.Errors["HTTP 403"] != 5 {
		t.Errorf("Errors = %v, want 5 recorded as HTTP 403", report.Errors)
	}
	if report.TTFB.Count != 0 {
		t.Errorf("failed requests leaked into the latency distribution: %+v", report.TTFB)
	}
}

func TestRunRefusesTwoPathsAtOnce(t *testing.T) {
	// Going through the boundary and straight to a socket are the two sides
	// of the comparison. Silently picking one would label a baseline as a
	// mesh measurement, or the reverse, and nothing downstream could tell.
	_, err := Run(context.Background(), Options{
		Target:     "http://localhost/v1/models",
		Requests:   1,
		Socket:     "/tmp/boundary.sock",
		UnixTarget: "/tmp/node.sock",
	})
	if err == nil {
		t.Error("Run accepted both a boundary and a direct socket")
	}
}

func TestRunRejectsAWorkloadItCannotMeasure(t *testing.T) {
	for _, opts := range []Options{
		{Requests: 1},
		{Target: "http://example.invalid"},
	} {
		if _, err := Run(context.Background(), opts); err == nil {
			t.Errorf("Run(%+v) accepted an unmeasurable workload", opts)
		}
	}
}
