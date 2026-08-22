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
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestOutcomeForNamesEveryDenialReasonSeparately(t *testing.T) {
	// A denial and an unreachable host mean opposite things about a
	// deployment: one is policy working, the other is the mesh failing.
	// Collapsing them would make the counters unusable as evidence.
	cases := []struct {
		err  error
		want string
	}{
		{nil, "allowed"},
		{fmt.Errorf("wrapped: %w", ErrNotAllowed), "denied"},
		{fmt.Errorf("wrapped: %w", ErrHostUnreachable), "unreachable"},
		{fmt.Errorf("wrapped: %w", ErrConnectionRefused), "refused"},
		{errors.New("something else"), "error"},
	}
	for _, tc := range cases {
		if got := outcomeFor(tc.err); got != tc.want {
			t.Errorf("outcomeFor(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestRouteKindStringsAreStableLabels(t *testing.T) {
	// These strings are metric label values, so renaming one silently breaks
	// every dashboard and every recorded experiment that used it.
	cases := map[RouteKind]string{
		RouteMeshEntrypoint: "mesh-entrypoint",
		RouteMeshService:    "mesh-service",
		RouteExternal:       "external",
	}
	for kind, want := range cases {
		if got := kind.String(); got != want {
			t.Errorf("RouteKind(%d).String() = %q, want %q", int(kind), got, want)
		}
	}
}

func TestCountedConnPropagatesHalfClose(t *testing.T) {
	// The relay half-closes to signal EOF upstream. If the wrapper swallows
	// CloseWrite, a peer waiting on EOF hangs until a timeout instead.
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	var closed bool
	c := &countedConn{Conn: halfCloser{Conn: client, onCloseWrite: func() { closed = true }}}
	if err := c.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if !closed {
		t.Error("CloseWrite did not reach the underlying connection")
	}
}

func TestCountedConnFallsBackToCloseWhenItCannotHalfClose(t *testing.T) {
	// The relay closes a connection outright when it cannot half-close, and
	// that full close is what unblocks the opposite copy. A wrapper that
	// advertises CloseWrite without delivering one defeats that fallback and
	// hangs the relay forever, which is a deadlock no metric test would show.
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	c := &countedConn{Conn: client} // net.Pipe cannot half-close

	// The deadline goes on before the close, both because a closed pipe will
	// not accept one and so the pre-fix behaviour reports a blocked read
	// rather than hanging the package for the whole test timeout.
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("read after CloseWrite = %v, want the connection closed", err)
	}
}

func TestCountedConnDecrementsOnceOnRepeatedClose(t *testing.T) {
	// Both relay directions close their side, so a naive decrement would run
	// twice and drive the active-flow gauge negative.
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	c := &countedConn{Conn: client}
	flowsActive.Set(0)
	flowsActive.Inc()

	_ = c.Close()
	_ = c.Close()

	if got := gaugeValue(t, flowsActive); got != 0 {
		t.Errorf("flowsActive = %v after two closes, want 0", got)
	}
}

// gaugeValue reads a gauge without pulling in the prometheus test helpers,
// which would add a module for one assertion.
func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatalf("read gauge: %v", err)
	}
	return m.GetGauge().GetValue()
}

// halfCloser adds CloseWrite to a connection that lacks one.
type halfCloser struct {
	net.Conn
	onCloseWrite func()
}

func (h halfCloser) CloseWrite() error {
	h.onCloseWrite()
	return nil
}
