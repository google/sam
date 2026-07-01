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
	"fmt"
	"maps"
	"net/url"
	"strings"

	"github.com/libp2p/go-libp2p/core/protocol"
)

// ============================================================================
// Libp2p Protocol & Network Constants
// ============================================================================

const (
	// EnrollProtocolID is the libp2p protocol identifier for node enrollment.
	EnrollProtocolID protocol.ID = "/sam/enroll/1.0.0"

	// MCPProtocolID is the libp2p protocol identifier for Model Context Protocol streams.
	MCPProtocolID protocol.ID = "/sam/mcp/1.0.0"

	// AuthProtocolID is the libp2p protocol identifier for the zero-trust auth handshake.
	AuthProtocolID protocol.ID = "/sam/auth/1.0.0"

	// GossipEvents is the GossipSub topic used to broadcast mesh event updates (e.g., node bans).
	GossipEvents = "/sam/mesh/events/v1"

	// GossipHubSync is the GossipSub topic used by the Hub to sync cluster state.
	GossipHubSync = "/sam/hub/sync/v1"

	// DefaultAudience is the default audience string used in OIDC token validation.
	DefaultAudience = "sam-mesh-audience"
)

// ============================================================================
// Service Classification & Namespaces
// ============================================================================

const (
	// SystemNamespace is the namespace reserved for built-in mesh services and protocols.
	SystemNamespace = "system"

	// CatalogTarget is the special system service name used to retrieve tool catalogs.
	// In policy rules, it must be referred to explicitly as: system://sam.catalog
	CatalogTarget = "sam.catalog"

	// MCPServicePrefix is the scheme prefix for Model Context Protocol services.
	// Fully qualified MCP services use the URI format: mcp://<service-name>
	MCPServicePrefix = "mcp://"

	// InferenceServicePrefix is the scheme prefix for LLM Inference services.
	// Fully qualified inference services use the URI format: inference://<service-name>
	InferenceServicePrefix = "inference://"
)

// ============================================================================
// Biscuit Authorization Facts
// ============================================================================

// Biscuit fact names represent the Datalog predicates used in auth tokens and policy evaluation.
const (
	FactExpiration             = "expiration"
	FactNode                   = "node"
	FactClientPeerID           = "client_peer_id"
	FactGroup                  = "group"
	FactRole                   = "role"
	FactUser                   = "user"
	FactEmail                  = "email"
	FactGrantedServiceAllTypes = "granted_service_all_types"
	FactGrantedServiceAll      = "granted_service_all"
	FactGrantedServiceSuffix   = "granted_service_suffix"
	FactGrantedServicePrefix   = "granted_service_prefix"
	FactGrantedServiceExact    = "granted_service_exact"

	FactGrantedTargetAllTypes = "granted_target_all_types"
	FactGrantedTargetAll      = "granted_target_all"
	FactGrantedTargetSuffix   = "granted_target_suffix"
	FactGrantedTargetPrefix   = "granted_target_prefix"
	FactGrantedTargetExact    = "granted_target_exact"
	FactGrantedTargetAllFacts = "granted_target_all_facts"
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
//  1. Define a constant for the Biscuit fact name in the constants block above
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

// ============================================================================
// Protocol Types & String Mappings
// ============================================================================

const (
	// ServiceTypeStringMCP is the string identifier for MCP services.
	ServiceTypeStringMCP = "mcp"

	// ServiceTypeStringInference is the string identifier for Inference services.
	ServiceTypeStringInference = "inference"
)

// ParseServiceType converts a string identifier (e.g. from JSON or REST) to the ServiceType protobuf enum.
func ParseServiceType(s string) (ServiceType, error) {
	switch strings.ToLower(s) {
	case ServiceTypeStringMCP:
		return ServiceType_SERVICE_TYPE_MCP, nil
	case ServiceTypeStringInference:
		return ServiceType_SERVICE_TYPE_INFERENCE, nil
	default:
		return ServiceType_SERVICE_TYPE_UNSPECIFIED, fmt.Errorf("invalid service type: %s", s)
	}
}

// ServiceTypeToString converts a ServiceType protobuf enum back to its standard string identifier.
func ServiceTypeToString(t ServiceType) (string, error) {
	switch t {
	case ServiceType_SERVICE_TYPE_MCP:
		return ServiceTypeStringMCP, nil
	case ServiceType_SERVICE_TYPE_INFERENCE:
		return ServiceTypeStringInference, nil
	default:
		return "", fmt.Errorf("invalid or unspecified service type")
	}
}

// ============================================================================
// Parsing & Routing Utilities
// ============================================================================

// ParseServiceTarget parses a service target string into its type (scheme) and name components.
//
// Expected formats:
//   - Hierarchical service URIs: "scheme://name" (e.g., "mcp://my_service") or "scheme://name/path" (e.g., "mcp://my_service/tool").
//   - Target facts: "fact:value" (e.g., "group:backend" or "user:bob").
//   - Wildcards: "*" (maps type to "*" and name to "*").
//
// If no scheme/colon is present, it returns an empty string for the type and the full target as the name.
// No fallback namespace is applied; callers must be explicit.
func ParseServiceTarget(target string) (svcType, svcName string) {
	if target == "*" {
		return "*", "*"
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" {
		return "", target
	}
	name := u.Host
	if u.Opaque != "" {
		name = u.Opaque
	} else if u.Path != "" {
		name = u.Host + u.Path
	}
	return u.Scheme, name
}
