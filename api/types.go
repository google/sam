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

package api

import (
	"maps"
	"strings"

	"github.com/libp2p/go-libp2p/core/protocol"
)

const EnrollProtocolID protocol.ID = "/sam/enroll/1.0.0"
const MCPProtocolID protocol.ID = "/sam/mcp/1.0.0"
const GossipEvents = "/sam/mesh/events/v1"
const GossipHubSync = "/sam/hub/sync/v1"
const AuthProtocolID protocol.ID = "/sam/auth/1.0.0"

// CatalogTarget is the special target service name used to retrieve tool catalogs from remote nodes.
const CatalogTarget = "/sam/catalog"

// DefaultServiceType is the default type for services without a namespace.
const DefaultServiceType = "system"

const DefaultAudience = "sam-mesh-audience"

// Biscuit fact names
const (
	FactExpiration    = "expiration"
	FactNode          = "node"
	FactClientPeerID  = "client_peer_id"
	FactGroup         = "group"
	FactRole          = "role"
	FactUser          = "user"
	FactEmail         = "email"
	FactAllowService  = "allow_service"
	FactNetworkTarget = "allow_network_target"
)

// oidcClaimToFact maps standard OIDC claims to their corresponding Biscuit facts.
//
// Specification References:
//   - OIDC Claims: Standard JWT payload claims are defined in OpenID Connect Core 1.0 section 5.1:
//     https://openid.net/specs/openid-connect-core-1_0.html#Claims
//   - Biscuit Symbols / Facts: The Biscuit symbol table and fact specification is defined at:
//     https://doc.biscuitsec.org/reference/specifications.html#symbol-table
//
// How to add a new translation:
//  1. Define a constant for the Biscuit fact name in the "Biscuit fact names" block above
//     (e.g., FactMyNewClaim = "my_new_fact").
//  2. Add an entry to the oidcClaimToFact map below (e.g., "my_oidc_claim": FactMyNewClaim).
//  3. Update translateClaimsToFacts in cmd/sam-hub/biscuit.go to handle parsing/type conversion
//     for the new fact if it uses a custom format (e.g. integer, date, list).
//  4. Implement unit tests in cmd/sam-hub/biscuit_test.go covering the new mapping.
var oidcClaimToFact = map[string]string{
	"sub":    FactUser,
	"email":  FactEmail,
	"groups": FactGroup,
}

// OIDCClaimToFact returns a copy of the OIDC claims to Biscuit facts map.
// This ensures that the global map is immutable and thread-safe for concurrent readers.
func OIDCClaimToFact() map[string]string {
	return maps.Clone(oidcClaimToFact)
}

// ParseServiceTarget parses a service target string into its type and name components.
// The target convention is "type:name" (e.g., "mcp:my_tool").
// If no colon is present, the type defaults to the "system" namespace.
// The global wildcard "*" is a special case that maps to type "*" and name "*".
func ParseServiceTarget(target string) (svcType, svcName string) {
	if target == "*" {
		return "*", "*"
	}
	parts := strings.SplitN(target, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return DefaultServiceType, target
}
