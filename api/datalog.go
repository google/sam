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

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
)

// ============================================================================
// SAM Datalog Authorization Concepts & Predicates
// ============================================================================
//
// SAM enforces security policies using Biscuit tokens containing Datalog facts,
// rules, and checks. Here are the core concepts used in our Datalog engine:
//
// 1. Replay Defense Facts:
//    - client_peer_id: The libp2p PeerID of the node that authenticated with the
//      Hub to request this token. Embedded in the token authority block.
//    - connection_peer_id: The libp2p PeerID of the caller initiating the connection
//      to the receiving node. Injected dynamically at runtime by the receiver.
//    - Replay Check: Verified using the check:
//      `check if client_peer_id($id), connection_peer_id($id)`
//      This guarantees that a token can only be used by its rightful owner.
//
// 2. Target Constraints & Resolution:
//    - target_fact(type, value): Standardized format representing an identity claim
//      (e.g., user, group, node ID) asserted by the caller. Derived dynamically at
//      runtime from OIDC claims or node authentication.
//    - allow_network_target: Derived fact generated on the receiver node by matching
//      target_fact against the token's allowed targets (e.g., granted_target_exact).
//    - target_unrestricted: Fact injected in the token by the Hub indicating that
//      the client has unrestricted network access and bypasses target constraints.
//    - Target Check: Verified using the check:
//      `check if allow_network_target($fact, $val) or target_unrestricted()`
//      If target_unrestricted is present, target checking succeeds immediately.
//      Otherwise, it requires a matching allow_network_target rule to succeed.
//
// For a high-level overview of policy translation and schemas, see the
// documentation in site/content/docs/development/policy.md.
//
// ============================================================================

// Biscuit fact names represent the Datalog predicates used in auth tokens and policy evaluation.
const (
	// FactExpiration defines the token expiration time.
	// Contains: biscuit.Date(expirationTime)
	// Example Datalog: check if time($time), expiration($exp), $time <= $exp
	FactExpiration = "expiration"

	// FactNode defines the PeerID of the node that this token belongs to.
	// Contains: biscuit.String(nodePeerID)
	// Example Datalog: allow if node("12D3KooWP2G8nJCLASp1Kb4TmQS4wCpMH2vpSUz8ug8DYEJiuf1i")
	FactNode = "node"

	// FactClientPeerID defines the client PeerID performing the request, used for replay defense.
	// Contains: biscuit.String(clientPeerID)
	// Example Datalog: check if client_peer_id($id), connection_peer_id($id)
	FactClientPeerID = "client_peer_id"

	// FactGroup defines the group claim extracted from the OIDC token.
	// Contains: biscuit.String(groupName)
	// Example Datalog: allow if group("data-science")
	FactGroup = "group"

	// FactRole defines a custom SAM role assigned to the user or node.
	// Contains: biscuit.String(roleName)
	// Example Datalog: allow if role("mesh-member")
	FactRole = "role"

	// FactUser defines the subject (username/userID) claim extracted from the OIDC token.
	// Contains: biscuit.String(username)
	// Example Datalog: allow if user("alice")
	FactUser = "user"

	// FactEmail defines the email claim extracted from the OIDC token.
	// Contains: biscuit.String(emailAddress)
	// Example Datalog: allow if email("bob@example.com")
	FactEmail = "email"

	// FactGrantedServiceAllTypes allows access to all service types (e.g., mcp, inference) and all targets.
	// Contains: (no terms)
	// Example Datalog: allow if granted_service_all_types()
	FactGrantedServiceAllTypes = "granted_service_all_types"

	// FactGrantedServiceAll allows access to all targets under a specific service type.
	// Contains: biscuit.String(serviceType) (e.g., "mcp")
	// Example Datalog: allow if service("mcp", $target), granted_service_all("mcp")
	FactGrantedServiceAll = "granted_service_all"

	// FactGrantedServiceSuffix allows access to services matching a suffix pattern (e.g. *.service.local).
	// Contains: biscuit.String(serviceType), biscuit.String(suffixPattern)
	FactGrantedServiceSuffix = "granted_service_suffix"

	// FactGrantedServicePrefix allows access to services matching a prefix pattern (e.g. calculator.*).
	// Contains: biscuit.String(serviceType), biscuit.String(prefixPattern)
	FactGrantedServicePrefix = "granted_service_prefix"

	// FactGrantedServiceExact allows access to a specific service type and target.
	// Contains: biscuit.String(serviceType), biscuit.String(targetName)
	// Example Datalog: allow if service("mcp", "calculator"), granted_service_exact("mcp", "calculator")
	FactGrantedServiceExact = "granted_service_exact"

	// FactGrantedTargetAllTypes allows target access to all network targets (unrestricted).
	// Contains: (no terms)
	FactGrantedTargetAllTypes = "granted_target_all_types"

	// FactGrantedTargetAll allows target access to all values of a specific fact.
	// Contains: biscuit.String(factName) (e.g., "group")
	FactGrantedTargetAll = "granted_target_all"

	// FactGrantedTargetSuffix allows target access to values matching a suffix pattern.
	// Contains: biscuit.String(factName), biscuit.String(suffixPattern)
	FactGrantedTargetSuffix = "granted_target_suffix"

	// FactGrantedTargetPrefix allows target access to values matching a prefix pattern.
	// Contains: biscuit.String(factName), biscuit.String(prefixPattern)
	FactGrantedTargetPrefix = "granted_target_prefix"

	// FactGrantedTargetExact allows target access to a specific fact name and value combination.
	// Contains: biscuit.String(factName), biscuit.String(factValue)
	// Example Datalog: allow_network_target("group", "backend") <- target_fact("group", "backend"), granted_target_exact("group", "backend")
	FactGrantedTargetExact = "granted_target_exact"

	// FactGrantedTargetAllFacts allows target access to any fact name and value combination.
	// Contains: (no terms)
	FactGrantedTargetAllFacts = "granted_target_all_facts"

	// FactConnectionPeerID defines the actual PeerID of the remote peer making the connection.
	// Contains: biscuit.String(connectionPeerID)
	// Example Datalog: check if client_peer_id($id), connection_peer_id($id)
	FactConnectionPeerID = "connection_peer_id"

	// FactTargetFact normalizes identity assertions (claims, node, user) to a standardized target.
	// Contains: biscuit.String(factName), biscuit.String(factValue)
	// Example Datalog: target_fact("group", $val) <- group($val)
	FactTargetFact = "target_fact"

	// FactAllowNetworkTarget evaluates whether a target assertion meets the token access grants.
	// Contains: biscuit.String(factName), biscuit.String(factValue)
	// Example Datalog: allow_network_target("group", "backend")
	FactAllowNetworkTarget = "allow_network_target"

	// FactTargetUnrestricted indicates that target authorization checks are bypassed.
	// Contains: (no terms)
	// Example Datalog: check if allow_network_target($fact, $val) or target_unrestricted()
	FactTargetUnrestricted = "target_unrestricted"

	// FactTargetRestricted indicates that target authorization checks must be enforced.
	// Contains: (no terms)
	FactTargetRestricted = "target_restricted"

	// FactService represents the service target that a node is requesting access to.
	// Contains: biscuit.String(serviceType), biscuit.String(serviceName)
	// Example Datalog: service("mcp", "calculator")
	FactService = "service"

	// FactTime defines the current system time injected during evaluation.
	// Contains: biscuit.Date(currentTime)
	// Example Datalog: check if time($time)
	FactTime = "time"
)

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

var (
	// BaselinePolicies are the pre-compiled authorization policies for the node middleware.
	BaselinePolicies []biscuit.Policy

	// BaselineRules are the pre-compiled target evaluation rules for the node middleware.
	BaselineRules []biscuit.Rule

	// BaselineReplayCheck verifies that the client peer ID matches the connection peer ID.
	BaselineReplayCheck biscuit.Check

	// BaselineTargetCheck verifies that the target matches one of the allowed network targets.
	BaselineTargetCheck biscuit.Check

	// TargetFactRules maps node and OIDC claims to target_fact datalog facts.
	TargetFactRules []biscuit.Rule

	// HubStaticTimeCheck is the standard check for verifying OIDC token expiration.
	HubStaticTimeCheck biscuit.Check

	// AllowIfTruePolicy is the static policy "allow if true" used during token verification.
	AllowIfTruePolicy biscuit.Policy
)

func init() {
	// 1. Service Allow Policies
	policyStrs := []string{
		fmt.Sprintf(`allow if %s($type, $name), %s($type, $name)`, FactService, FactGrantedServiceExact),
		fmt.Sprintf(`allow if %s($type, $name), %s($type, $prefix), $name.starts_with($prefix)`, FactService, FactGrantedServicePrefix),
		fmt.Sprintf(`allow if %s($type, $name), %s($type, $suffix), $name.ends_with($suffix)`, FactService, FactGrantedServiceSuffix),
		fmt.Sprintf(`allow if %s($type, $name), %s($type)`, FactService, FactGrantedServiceAll),
		fmt.Sprintf(`allow if %s($type, $name), %s()`, FactService, FactGrantedServiceAllTypes),
		fmt.Sprintf(`allow if %s(%q, "%s")`, FactService, SystemNamespace, CatalogTarget),
	}

	for i, pStr := range policyStrs {
		p, err := parser.FromStringPolicy(pStr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse baseline policy %d: %v", i, err))
		}
		BaselinePolicies = append(BaselinePolicies, p)
	}

	// 2. Target Evaluation Rules
	// These rules satisfy the check if allow_network_target($fact, $val) injected by the Hub.
	ruleStrs := []string{
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s($fact, $val)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetExact),
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s($fact, $prefix), $val.starts_with($prefix)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetPrefix),
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s($fact, $suffix), $val.ends_with($suffix)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetSuffix),
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s($fact)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetAll),
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s()`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetAllFacts),
	}

	for i, rStr := range ruleStrs {
		r, err := parser.FromStringRule(rStr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse baseline rule %d: %v", i, err))
		}
		BaselineRules = append(BaselineRules, r)
	}

	var err error
	BaselineReplayCheck, err = parser.FromStringCheck(fmt.Sprintf(`check if %s($id), %s($id)`, FactClientPeerID, FactConnectionPeerID))
	if err != nil {
		panic(fmt.Sprintf("failed to parse replay check: %v", err))
	}

	BaselineTargetCheck, err = parser.FromStringCheck(fmt.Sprintf(`check if %s($fact, $val) or %s()`, FactAllowNetworkTarget, FactTargetUnrestricted))
	if err != nil {
		panic(fmt.Sprintf("failed to parse target check: %v", err))
	}

	for _, val := range OIDCClaimToFact() {
		ruleStr := fmt.Sprintf(`%s(%q, $val) <- %s($val)`, FactTargetFact, val, val)
		r, err := parser.FromStringRule(ruleStr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse target fact rule: %v", err))
		}
		TargetFactRules = append(TargetFactRules, r)
	}

	r, err := parser.FromStringRule(fmt.Sprintf(`%s(%q, $val) <- %s($val)`, FactTargetFact, FactNode, FactNode))
	if err != nil {
		panic(fmt.Sprintf("failed to parse node fact rule: %v", err))
	}
	TargetFactRules = append(TargetFactRules, r)

	HubStaticTimeCheck, err = parser.FromStringCheck(fmt.Sprintf(`check if %s($time), %s($exp), $time <= $exp`, FactTime, FactExpiration))
	if err != nil {
		panic(fmt.Sprintf("failed to parse static time check: %v", err))
	}

	AllowIfTruePolicy, err = parser.FromStringPolicy("allow if true")
	if err != nil {
		panic(fmt.Sprintf("failed to parse static allow policy: %v", err))
	}
}
