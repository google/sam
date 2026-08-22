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
	"context"
	"net/http"

	"github.com/google/sam/api"
)

// An agent has no key and no enrolment: it is a sandbox, and giving every
// sandbox a mesh identity is the cost this design exists to avoid. So the node
// it runs behind speaks for it, naming the agent alongside its own token.
//
// What this covers: attribution and policy on both datapaths. A peer can
// authorize and audit "agent reviewer-7 called me", not merely "some node did",
// and it can do so with the existing vocabulary because the claim is injected
// as an ordinary agent() fact. HTTP requests carry it in api.HeaderSamAgent;
// libp2p streams carry it in the AuthFrame, bound to the MCP session rather
// than the request, since the SDK gives a tool handler the session's context.
//
// What it does not cover, and cannot:
//
//   - Proof. The claim is the calling node's word. A node that lies can name
//     any agent, so a mesh that cares must also constrain which peers may speak
//     for which agent namespaces. This is not a weakness of carrying the claim
//     beside the token: an appended Biscuit block would be exactly as forgeable
//     by the same party, and is invisible to the authorizer besides (see
//     internal/identity's TestAttenuationBlockFactsAreInvisibleToTheAuthorizer).
//     Only a block signed by the agent's own key would be proof, which needs
//     third-party blocks that biscuit-go does not implement.
//   - Anything an agent does that never leaves its node.
//
// One consequence worth knowing before writing such a policy: a node's own
// housekeeping carries no agent, because no agent asked for it. A provider
// whose policy demands an agent therefore also refuses that node's model
// catalog probe, and its models stop appearing in peers' /v1/models listings
// even though agents can still call them. Policies that mean to gate agent
// traffic should say so, rather than demanding an agent unconditionally.

// agentFromLocalGateway returns the agent a local gateway is speaking for.
//
// Only the node's Unix socket can name an agent: its permissions are the
// credential, so a caller that reached it is the gateway that admitted the
// sandbox. A claim arriving over TCP is from something that is not the gateway
// and is dropped.
//
// An invalid identifier is dropped rather than rejected. The request continues
// unattributed, which is the same position the mesh was in before agents
// existed, and refusing outright would turn a malformed bundle into an outage.
func agentFromLocalGateway(r *http.Request) string {
	if !fromLocalSocket(r) {
		return ""
	}
	agentID := agentClaim(r.Header.Get(api.HeaderSamAgent))
	recordAgentSeen(agentID)
	return agentID
}

// agentClaim validates an agent identifier arriving from elsewhere, returning
// "" for anything malformed so a bad claim is worth no more than no claim.
func agentClaim(agentID string) string {
	if agentID == "" {
		return ""
	}
	if err := api.ValidateAgentID(agentID); err != nil {
		logger.Warnf("[Auth] Ignoring malformed agent claim %q: %v", agentID, err)
		return ""
	}
	return agentID
}

type agentContextKey struct{}

// contextWithAgent carries the agent an MCP session belongs to down to the code
// that opens streams on its behalf.
//
// The MCP SDK hands a tool handler the session's context, not the HTTP
// request's, so the agent is bound once when the session's server is built
// (NewMCPHandler) rather than read per request. That matches how sandboxes
// work: one gateway serves one agent, so one session belongs to one agent for
// its whole life.
func contextWithAgent(ctx context.Context, agentID string) context.Context {
	if agentID == "" {
		return ctx
	}
	return context.WithValue(ctx, agentContextKey{}, agentID)
}

// agentFromContext returns the agent a request is being made for, if any.
func agentFromContext(ctx context.Context) string {
	agentID, _ := ctx.Value(agentContextKey{}).(string)
	return agentID
}
