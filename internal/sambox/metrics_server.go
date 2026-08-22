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
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ServeMetrics exposes this boundary's counters on addr until ctx ends.
//
// It is off unless an operator asks for it. The boundary sits between a
// sandbox and the mesh, so any listener it opens is one more thing reachable
// from wherever addr is bound; an experiment wants the numbers, a production
// sandbox usually does not. Nothing here is authenticated, which is why the
// caller has to name the address rather than get one by default.
func ServeMetrics(ctx context.Context, addr string) (*http.Server, error) {
	if addr == "" {
		return nil, errors.New("sambox: no metrics address configured")
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()
	go func() {
		_ = server.Serve(listener)
	}()

	return server, nil
}
