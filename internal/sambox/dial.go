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
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// dialTimeout bounds opening a destination. The SOCKS5 layer deliberately drops
// its handshake deadline before dialling, so this is the only bound and it has
// to exist here.
const dialTimeout = 30 * time.Second

// AgentDialer opens whatever a Route calls for. It is the only place in the
// sandbox boundary that touches the network, which keeps the routing decision
// (route.go) and the protocol (socks5.go) free of I/O.
type AgentDialer struct {
	// Router classifies destinations. Required.
	Router *Router

	// SidecarSocket is the Unix socket of the sam-node this sandbox is attached
	// to. sam-box is the node's only consumer here: an agent never reaches the
	// socket, only the curated surface built on top of it (entrypoint.go).
	SidecarSocket string

	// AgentID is the principal this boundary serves, asserted to the node on
	// every request (api.HeaderSamAgent). Empty means the sandbox is
	// unidentified, and mesh policy sees only the node it came through.
	AgentID string

	// Ingress serves what the agent is permitted to advertise. Nil means the
	// agent may serve nothing, which is the case for a sandbox that only calls
	// out.
	Ingress *IngressManager

	// DialContext opens external destinations. Nil uses a plain net.Dialer;
	// tests and future egress interception replace it.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// DialDestination implements Dialer.
func (d *AgentDialer) DialDestination(ctx context.Context, _ *Credentials, dst Destination) (net.Conn, error) {
	if d.Router == nil {
		return nil, errors.New("sambox: AgentDialer requires a Router")
	}

	start := time.Now()

	route, err := d.Router.Route(dst)
	if err != nil {
		recordFlow(routeUnresolved, 0, err)
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	conn, err := d.dialRoute(ctx, route, dst)
	recordFlow(route.Kind.String(), time.Since(start), err)
	if err != nil {
		return nil, err
	}
	flowsActive.Inc()
	return &countedConn{Conn: conn}, nil
}

func (d *AgentDialer) dialRoute(ctx context.Context, route Route, dst Destination) (net.Conn, error) {
	switch route.Kind {
	case RouteMeshEntrypoint:
		return d.dialMeshEntrypoint()
	case RouteExternal:
		return d.dial(ctx, "tcp", dst.Address())
	case RouteMeshService:
		return d.dialMeshService(ctx, route)
	default:
		return nil, fmt.Errorf("sambox: unhandled route %v", route.Kind)
	}
}

// countedConn keeps the active-flow gauge honest. Both relay directions close
// their side, so the decrement has to happen exactly once.
type countedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *countedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		flowsActive.Dec()
	}
	return c.Conn.Close()
}

// CloseWrite keeps the half-close the relay depends on reachable through the
// wrapper. Advertising it unconditionally would be a trap: the relay falls back
// to a full close for connections that cannot half-close, and a wrapper that
// claims the capability without delivering it leaves the peer's copy blocked
// forever. So when the wrapped connection has no half-close, do what the relay
// would have done.
func (c *countedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

func (d *AgentDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if address == "" {
		return nil, fmt.Errorf("sambox: no %s address configured", network)
	}

	dial := d.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	conn, err := dial(ctx, network, address)
	if err != nil {
		return nil, classifyDialError(err)
	}
	return conn, nil
}

// classifyDialError maps a dial failure onto the vocabulary the SOCKS5 layer
// can report, so an agent sees "refused" or "unreachable" rather than a
// generic failure it cannot act on.
func classifyDialError(err error) error {
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("%w: %v", ErrConnectionRefused, err)
	case errors.As(err, &dnsErr),
		errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETUNREACH):
		return fmt.Errorf("%w: %v", ErrHostUnreachable, err)
	default:
		return err
	}
}
