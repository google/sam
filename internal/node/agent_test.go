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
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/sam/api"
)

// localSocketConn looks like a connection accepted on the node's Unix socket,
// which is what markLocalSocketConn keys off.
type localSocketConn struct{ net.Conn }

func (localSocketConn) LocalAddr() net.Addr {
	return &net.UnixAddr{Name: "/run/sam/node.sock", Net: "unix"}
}

func requestWithAgent(agentID string, overSocket bool) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/sam/12D3KooWpeer/mcp/svc", nil)
	if agentID != "" {
		req.Header.Set(api.HeaderSamAgent, agentID)
	}
	if overSocket {
		req = req.WithContext(markLocalSocketConn(req.Context(), localSocketConn{}))
	}
	return req
}

func TestAgentFromLocalGateway(t *testing.T) {
	tests := []struct {
		name       string
		agentID    string
		overSocket bool
		want       string
	}{
		{
			name:       "named by the local gateway",
			agentID:    "reviewer-7.prod.acme.example",
			overSocket: true,
			want:       "reviewer-7.prod.acme.example",
		},
		{
			// The socket is what identifies the gateway, so a claim from
			// anywhere else is from something that is not the gateway. Honouring
			// it would let any local process with the API token speak for any
			// agent.
			name:       "claimed over TCP",
			agentID:    "privileged.prod.acme.example",
			overSocket: false,
			want:       "",
		},
		{name: "no claim", overSocket: true, want: ""},
		{name: "malformed identifier", agentID: "not a valid id", overSocket: true, want: ""},
		{name: "a pattern rather than an identity", agentID: "*.prod.acme.example", overSocket: true, want: ""},
		{name: "an identifier with no authority", agentID: "reviewer", overSocket: true, want: ""},
		{name: "uppercase, which DNS cannot distinguish", agentID: "Reviewer.acme.example", overSocket: true, want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := agentFromLocalGateway(requestWithAgent(tc.agentID, tc.overSocket)); got != tc.want {
				t.Errorf("agentFromLocalGateway = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAgentClaimDropsRatherThanRejects: an unattributed request is the position
// the mesh was in before agents existed, whereas refusing would turn one
// malformed bundle into an outage for that sandbox.
func TestAgentClaimDropsRatherThanRejects(t *testing.T) {
	for _, claim := range []string{"", "not a valid id", "*.acme.example", "UPPER.acme.example"} {
		if got := agentClaim(claim); got != "" {
			t.Errorf("agentClaim(%q) = %q, want it dropped", claim, got)
		}
	}
	if got := agentClaim("reviewer.acme.example"); got != "reviewer.acme.example" {
		t.Errorf("agentClaim dropped a valid identifier: %q", got)
	}
}
