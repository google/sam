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

// Package bench drives a reproducible agent workload against the mesh.
//
// The chaos agent that ships with the repo is the realism story: a real model
// deciding what to call next. That makes it useless as an instrument, because
// two runs never issue the same requests and a difference between them cannot
// be attributed to the thing under test. This package is the opposite trade:
// it does exactly what it is told, so a difference between two runs is a
// difference in the mesh.
//
// It reaches the mesh the way an agent does, through the sandbox boundary's
// SOCKS5 socket, so what it measures is what an agent would experience rather
// than what an operator with host access would.
package bench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// Options describe one measurement run. The zero value is not useful: at
// minimum a Target and a positive Requests count are required.
type Options struct {
	// Socket is the sandbox boundary's SOCKS5 Unix socket. Empty measures the
	// same workload without the boundary, which is the baseline the mesh
	// numbers are only meaningful against.
	Socket string

	// UnixTarget dials the target over this Unix socket instead of resolving
	// its host. It is how the baseline reaches the node's own API without a
	// relay in between: putting one there, socat or otherwise, would add a
	// userspace hop to the baseline and quietly flatter everything measured
	// against it.
	UnixTarget string

	// Target is the URL to request, e.g. http://mesh.sam.alt/v1/models.
	Target string

	// Method and Body are the request to issue. An empty Method means GET.
	Method string
	Body   []byte

	// Header carries anything the target needs, such as a content type.
	Header http.Header

	// Requests is how many to issue in total, after warmup.
	Requests int

	// Concurrency is how many are in flight at once.
	Concurrency int

	// Warmup requests are issued and discarded before measurement starts, so
	// first-call costs (DHT lookup, provider discovery, connection setup) do
	// not contaminate the steady-state distribution. They are reported
	// separately rather than thrown away.
	Warmup int

	// NewFlowPerRequest opens a fresh boundary flow for every request instead
	// of reusing connections. This separates the cost of admitting a flow from
	// the cost of carrying one, which are different questions.
	NewFlowPerRequest bool

	// Timeout bounds a single request.
	Timeout time.Duration
}

// Sample is one completed request.
type Sample struct {
	// TTFB is the time until the response headers were available, which is
	// what an agent waiting on a first token actually experiences.
	TTFB time.Duration

	// Total additionally includes reading the body to completion.
	Total time.Duration

	// Status is the HTTP status, or 0 if the request never got one.
	Status int

	// Err is set when the request did not complete.
	Err error
}

// Report is the outcome of a run, in a shape that serialises to JSON for
// later analysis without needing the raw samples.
type Report struct {
	Target            string        `json:"target"`
	ThroughBoundary   bool          `json:"through_boundary"`
	NewFlowPerRequest bool          `json:"new_flow_per_request"`
	Concurrency       int           `json:"concurrency"`
	Requests          int           `json:"requests"`
	Warmup            int           `json:"warmup"`
	Succeeded         int           `json:"succeeded"`
	Failed            int           `json:"failed"`
	Elapsed           float64       `json:"elapsed_seconds"`
	Throughput        float64       `json:"requests_per_second"`
	TTFB              Distribution  `json:"ttfb_ms"`
	Total             Distribution  `json:"total_ms"`
	WarmupTTFB        *Distribution `json:"warmup_ttfb_ms,omitempty"`

	// Errors counts failures by their message, so a run that mostly failed
	// cannot be mistaken for a fast one.
	Errors map[string]int `json:"errors,omitempty"`
}

// Distribution summarises a set of latencies in milliseconds. Percentiles are
// computed from the full sorted sample rather than from bucketed counts, so
// they are exact for the run rather than an interpolation.
type Distribution struct {
	Count int     `json:"count"`
	Min   float64 `json:"min"`
	Mean  float64 `json:"mean"`
	P50   float64 `json:"p50"`
	P90   float64 `json:"p90"`
	P95   float64 `json:"p95"`
	P99   float64 `json:"p99"`
	Max   float64 `json:"max"`
	// StdDev is reported so a reader can see whether a mean is describing
	// anything, rather than averaging a bimodal distribution into fiction.
	StdDev float64 `json:"stddev"`
}

// Run issues the workload and returns its report.
func Run(ctx context.Context, opts Options) (*Report, error) {
	if opts.Target == "" {
		return nil, errors.New("bench: no target")
	}
	if opts.Requests <= 0 {
		return nil, errors.New("bench: no requests to issue")
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 1
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}

	client, err := newClient(opts)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()

	report := &Report{
		Target:            opts.Target,
		ThroughBoundary:   opts.Socket != "",
		NewFlowPerRequest: opts.NewFlowPerRequest,
		Concurrency:       opts.Concurrency,
		Requests:          opts.Requests,
		Warmup:            opts.Warmup,
		Errors:            map[string]int{},
	}

	if opts.Warmup > 0 {
		warm := issue(ctx, client, opts, opts.Warmup)
		d := summarise(ttfbOf(warm))
		report.WarmupTTFB = &d
	}

	start := time.Now()
	samples := issue(ctx, client, opts, opts.Requests)
	report.Elapsed = time.Since(start).Seconds()
	if report.Elapsed > 0 {
		report.Throughput = float64(len(samples)) / report.Elapsed
	}

	var ok []Sample
	for _, s := range samples {
		if s.Err != nil {
			report.Failed++
			report.Errors[s.Err.Error()]++
			continue
		}
		if s.Status >= 400 {
			report.Failed++
			report.Errors[fmt.Sprintf("HTTP %d", s.Status)]++
			continue
		}
		report.Succeeded++
		ok = append(ok, s)
	}

	report.TTFB = summarise(ttfbOf(ok))
	report.Total = summarise(totalOf(ok))
	return report, nil
}

// issue runs n requests at the configured concurrency.
func issue(ctx context.Context, client *http.Client, opts Options, n int) []Sample {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		samples = make([]Sample, 0, n)
		work    = make(chan struct{})
	)

	for range opts.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range work {
				s := once(ctx, client, opts)
				mu.Lock()
				samples = append(samples, s)
				mu.Unlock()
			}
		}()
	}

	for range n {
		select {
		case work <- struct{}{}:
		case <-ctx.Done():
			close(work)
			wg.Wait()
			return samples
		}
	}
	close(work)
	wg.Wait()
	return samples
}

// once issues a single request and times it.
func once(ctx context.Context, client *http.Client, opts Options) Sample {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	method := opts.Method
	if method == "" {
		method = http.MethodGet
	}

	var body io.Reader
	if len(opts.Body) > 0 {
		body = bytes.NewReader(opts.Body)
	}

	req, err := http.NewRequestWithContext(ctx, method, opts.Target, body)
	if err != nil {
		return Sample{Err: err}
	}
	for k, values := range opts.Header {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Sample{Err: err}
	}
	ttfb := time.Since(start)

	// The body has to be drained for the connection to be reusable, and
	// draining is part of what a caller waits for, so it is timed too.
	_, copyErr := io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	total := time.Since(start)

	if copyErr != nil {
		return Sample{Err: copyErr, Status: resp.StatusCode}
	}
	if closeErr != nil {
		return Sample{Err: closeErr, Status: resp.StatusCode}
	}
	return Sample{TTFB: ttfb, Total: total, Status: resp.StatusCode}
}

// newClient builds the transport the workload runs over. Through a boundary it
// dials the SOCKS5 socket, which is the only path a sandboxed agent has.
func newClient(opts Options) (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConnsPerHost: opts.Concurrency,
		DisableKeepAlives:   opts.NewFlowPerRequest,
	}

	switch {
	case opts.Socket != "" && opts.UnixTarget != "":
		return nil, errors.New("bench: a run goes through the boundary or straight to a socket, not both")
	case opts.Socket != "":
		dialer, err := proxy.SOCKS5("unix", opts.Socket, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("bench: dial boundary %s: %w", opts.Socket, err)
		}
		contextDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("bench: SOCKS5 dialer does not support contexts")
		}
		transport.DialContext = contextDialer.DialContext
	case opts.UnixTarget != "":
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", opts.UnixTarget)
		}
	default:
		transport.DialContext = (&net.Dialer{}).DialContext
	}

	return &http.Client{Transport: transport}, nil
}

func ttfbOf(samples []Sample) []time.Duration {
	out := make([]time.Duration, 0, len(samples))
	for _, s := range samples {
		if s.Err == nil {
			out = append(out, s.TTFB)
		}
	}
	return out
}

func totalOf(samples []Sample) []time.Duration {
	out := make([]time.Duration, 0, len(samples))
	for _, s := range samples {
		if s.Err == nil {
			out = append(out, s.Total)
		}
	}
	return out
}

// summarise reduces latencies to a distribution in milliseconds.
func summarise(values []time.Duration) Distribution {
	if len(values) == 0 {
		return Distribution{}
	}

	ms := make([]float64, len(values))
	for i, v := range values {
		ms[i] = float64(v.Nanoseconds()) / 1e6
	}
	sort.Float64s(ms)

	var sum float64
	for _, v := range ms {
		sum += v
	}
	mean := sum / float64(len(ms))

	var variance float64
	for _, v := range ms {
		variance += (v - mean) * (v - mean)
	}
	variance /= float64(len(ms))

	return Distribution{
		Count:  len(ms),
		Min:    ms[0],
		Mean:   mean,
		P50:    percentile(ms, 50),
		P90:    percentile(ms, 90),
		P95:    percentile(ms, 95),
		P99:    percentile(ms, 99),
		Max:    ms[len(ms)-1],
		StdDev: math.Sqrt(variance),
	}
}

// percentile returns the p-th percentile of sorted values using the
// nearest-rank method, which never invents a value that was not observed.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}
