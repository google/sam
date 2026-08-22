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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/google/sam/api"
)

// Reaching a named mesh service is the one destination that is not a byte pipe.
// The agent speaks HTTP to "openrouter.inference.sam.alt", while the sidecar
// routes by path, so somebody has to discover a provider and rewrite the
// request onto /sam/<peer>/<type>/<name>. That happens here, on an in-process
// HTTP server whose other end is handed back to the SOCKS5 layer as an ordinary
// connection.

const (
	// maxDiscoverBody bounds the discovery response. It is small and local, but
	// it is still parsed input and gets a limit like any other.
	maxDiscoverBody = 1 << 20

	// sidecarHost is a placeholder authority: the transport dials the Unix
	// socket, so the host in the URL is never resolved.
	sidecarHost = "sam-node"
)

// dialMeshService resolves the service to a provider and returns a connection
// that carries the agent's HTTP through to it.
func (d *AgentDialer) dialMeshService(ctx context.Context, route Route) (net.Conn, error) {
	if d.SidecarSocket == "" {
		return nil, fmt.Errorf("sambox: no sidecar socket configured")
	}

	svcType, svcName := api.ParseServiceTarget(route.ServiceURI)
	peerID, err := d.discoverProvider(ctx, svcType, svcName)
	if err != nil {
		return nil, err
	}

	transport := d.sidecarTransport()
	prefix := "/sam/" + peerID + "/" + svcType + "/" + svcName

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "http"
			r.Out.URL.Host = sidecarHost
			r.Out.Host = sidecarHost
			r.Out.URL.Path = prefix + r.In.URL.Path
			r.Out.URL.RawPath = ""
			d.assertAgent(r)
		},
		Transport: transport,
	}

	return serveOnPipe(proxy), nil
}

// serveOnPipe runs h on one end of an in-memory connection and hands back the
// other, so an HTTP handler can be given to the SOCKS5 layer as an ordinary
// connection.
func serveOnPipe(h http.Handler) net.Conn {
	agentSide, boundarySide := net.Pipe()
	server := &http.Server{
		Handler: h,
		// Mirrors the sidecar: bound header reads, but let bodies and responses
		// stream, since inference completions and MCP sessions legitimately do.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		_ = server.Serve(newSingleConnListener(boundarySide))
	}()
	return agentSide
}

// discoverProvider asks the sidecar which peers serve the requested service.
// A well-formed name with no provider is unreachable rather than forbidden:
// unlike a malformed mesh name, it tells a sandbox nothing it could not already
// learn from the tool catalog it is allowed to read.
func (d *AgentDialer) discoverProvider(ctx context.Context, svcType, svcName string) (string, error) {
	endpoint := (&url.URL{
		Scheme:   "http",
		Host:     sidecarHost,
		Path:     "/sam/service/discover",
		RawQuery: url.Values{"type": {svcType}, "name": {svcName}}.Encode(),
	}).String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}

	// No credential: reaching the sidecar's Unix socket is itself the proof of
	// authorization, which is why sam-box holds no sidecar token.
	resp, err := (&http.Client{Transport: d.sidecarTransport()}).Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: discovery failed: %v", ErrHostUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: discovery returned %s", ErrHostUnreachable, resp.Status)
	}

	var providers []*api.DiscoveredProvider
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDiscoverBody)).Decode(&providers); err != nil {
		return "", fmt.Errorf("%w: malformed discovery response: %v", ErrHostUnreachable, err)
	}
	for _, p := range providers {
		if p.GetPeerId() != "" {
			// The sidecar already scores and orders providers; taking the first
			// keeps that decision in one place.
			return p.GetPeerId(), nil
		}
	}
	return "", fmt.Errorf("%w: no provider for %s://%s", ErrHostUnreachable, svcType, svcName)
}

func (d *AgentDialer) sidecarTransport() http.RoundTripper {
	return sidecarTransport(d.SidecarSocket)
}

// sidecarTransport dials the node's API socket whatever host a URL names, since
// the host in these URLs is a placeholder and never resolved.
func sidecarTransport(socket string) http.RoundTripper {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}
}

// singleConnListener hands one already-established connection to an
// http.Server and then blocks, so the server lives exactly as long as the
// agent's connection does.
type singleConnListener struct {
	conn net.Conn

	accept  sync.Once
	closing sync.Once
	closed  chan struct{}
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, closed: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.accept.Do(func() { conn = l.conn })
	if conn != nil {
		return conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.closing.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
