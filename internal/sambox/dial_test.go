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
	"testing"

	"github.com/google/sam/api"
)

// closedTCPAddr returns an address nothing is listening on.
func closedTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

func mustEgressPolicy(t *testing.T, allow ...string) *EgressPolicy {
	t.Helper()
	p, err := NewEgressPolicy(allow)
	if err != nil {
		t.Fatalf("NewEgressPolicy: %v", err)
	}
	return p
}

func TestExternalDestinationRequiresPolicy(t *testing.T) {
	d := &AgentDialer{Router: &Router{Egress: mustEgressPolicy(t, "127.0.0.1")}}

	echo := startEcho(t)
	host, port, err := net.SplitHostPort(echo)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	dst := Destination{Name: host, Port: atoiPort(t, port)}

	conn, err := d.DialDestination(context.Background(), nil, dst)
	if err != nil {
		t.Fatalf("allowlisted destination was refused: %v", err)
	}
	_ = conn.Close()

	denied := Destination{Name: "evil.example", Port: 443, IsName: true}
	if _, err := d.DialDestination(context.Background(), nil, denied); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("DialDestination(%s) = %v, want ErrNotAllowed", denied, err)
	}
}

// TestRefusedDestinationIsReportedAsRefused pins the error mapping: an agent
// should be able to tell "nothing is listening" from "you may not go there".
func TestRefusedDestinationIsReportedAsRefused(t *testing.T) {
	closed := closedTCPAddr(t)
	host, port, err := net.SplitHostPort(closed)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	d := &AgentDialer{Router: &Router{Egress: mustEgressPolicy(t, host)}}

	_, err = d.DialDestination(context.Background(), nil, Destination{Name: host, Port: atoiPort(t, port)})
	if !errors.Is(err, ErrConnectionRefused) {
		t.Fatalf("DialDestination to a closed port = %v, want ErrConnectionRefused", err)
	}
	if code := replyCodeFor(err); code != replyConnectionRefused {
		t.Errorf("reply code = %#x, want %#x", code, replyConnectionRefused)
	}
}

func TestUnresolvableDestinationIsReportedAsUnreachable(t *testing.T) {
	d := &AgentDialer{Router: &Router{Egress: mustEgressPolicy(t, "*.invalid")}}

	_, err := d.DialDestination(context.Background(), nil, Destination{
		Name:   "nothing.here.invalid",
		Port:   443,
		IsName: true,
	})
	if !errors.Is(err, ErrHostUnreachable) {
		t.Fatalf("DialDestination to an unresolvable name = %v, want ErrHostUnreachable", err)
	}
}

func TestDialerRequiresARouter(t *testing.T) {
	var d AgentDialer
	if _, err := d.DialDestination(context.Background(), nil, Destination{
		Name:   api.MeshEntrypointHost,
		Port:   80,
		IsName: true,
	}); err == nil {
		t.Fatal("DialDestination with no router succeeded, want an error")
	}
}

func atoiPort(t *testing.T, port string) uint16 {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("ResolveTCPAddr: %v", err)
	}
	return uint16(addr.Port)
}
