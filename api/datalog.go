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
	"sort"
	"strings"

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
//      control plane to request this token. Embedded in the token authority block.
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
//    - target_unrestricted: Fact injected in the token by the control plane indicating that
//      the client has unrestricted network access and bypasses target constraints.
//    - Target Check: Verified using the check:
//      `check if allow_network_target($fact, $val) or target_unrestricted()`
//      If target_unrestricted is present, target checking succeeds immediately.
//      Otherwise, it requires a matching allow_network_target rule to succeed.
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

	// FactAgent defines the agent on whose behalf a request is made. Unlike
	// FactNode it does not identify a host: it is appended to the token when an
	// agent is admitted, and the same identifier is asserted again wherever that
	// agent is next resumed. See api/agent.go for the identifier rules.
	// Contains: biscuit.String(agentID)
	// Example Datalog: allow if agent("reviewer-7.prod.acme.example")
	FactAgent = "agent"

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

	// FactRight defines the cryptographically signed capability/right.
	// Contains: biscuit.String(rightName)
	// Example Datalog: allow if right("relay")
	FactRight = "right"

	// RightRelay defines the transport relaying/bridging right.
	RightRelay = "relay"

	// RightServiceInvoke defines the edge service invocation right.
	RightServiceInvoke = "service:invoke"

	// Standard role values
	RoleRouter = "sam:role:router"
	RoleNode   = "sam:role:node"
	RoleSamBox = "sam:role:sambox"

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

	// FactGrantedServiceSet allows access to a Set of exact service names under a specific service
	// type. This lets many exact grants for the same type be carried as a single Datalog fact instead
	// of one fact per entry, which keeps token/world fact counts flat regardless of list length.
	// Contains: biscuit.String(serviceType), biscuit.Set of biscuit.String(serviceName)
	// Example Datalog: allow if service("mcp", "calculator"), granted_service_set("mcp", $set), $set.contains("calculator")
	FactGrantedServiceSet = "granted_service_set"

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

	// FactGrantedTargetSet allows target access to a Set of exact values for a specific fact name.
	// This lets many exact target grants for the same fact name be carried as a single Datalog fact
	// instead of one fact per entry, which keeps token/world fact counts flat regardless of list length.
	// Contains: biscuit.String(factName), biscuit.Set of biscuit.String(factValue)
	FactGrantedTargetSet = "granted_target_set"

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

	// FactLabel is a control-plane-attested key=value label on the token's
	// node (see api/labels.go). The control plane mints one fact per
	// declared label, so a requirement is a single exact match: a node
	// attested with region="us-east-1" carries label("region", "us-east-1"),
	// satisfying `check if label("region", "us-east-1")` only — composition
	// across values is left entirely to the operator (attest as many labels
	// as needed). Distinct from the unauthenticated gossip routing hint
	// carried in ServiceAnnounce.labels.
	// Contains: biscuit.String(key), biscuit.String(value)
	// Example Datalog: check if label("region", "us-east-1")
	FactLabel = "label"

	// FactTime defines the current system time injected during evaluation.
	// Contains: biscuit.Date(currentTime)
	// Example Datalog: check if time($time)
	FactTime = "time"
)

var oidcClaimToFact = map[string]string{
	"sub":    FactUser,
	"email":  FactEmail,
	"groups": FactGroup,
	"roles":  FactRole,
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

	// ControlPlaneStaticTimeCheck is the standard check for verifying OIDC token expiration.
	ControlPlaneStaticTimeCheck biscuit.Check

	// AllowIfTruePolicy is the static policy "allow if true" used during token verification.
	AllowIfTruePolicy biscuit.Policy
)

func init() {
	// 1. Service Allow Policies
	policyStrs := []string{
		// Exact Match: Allows access if the token possesses a granted_service_exact fact
		// that perfectly matches both the protocol type (e.g. "mcp") and the service name (e.g. "calculator").
		fmt.Sprintf(`allow if %s($type, $name), %s($type, $name)`, FactService, FactGrantedServiceExact),

		// Exact Set Match: Allows access if the token possesses a granted_service_set fact for the given
		// protocol type whose Set of names contains the requested service name.
		fmt.Sprintf(`allow if %s($type, $name), %s($type, $set), $set.contains($name)`, FactService, FactGrantedServiceSet),

		// Prefix Match: Allows access if the token possesses a granted_service_prefix fact
		// for the given protocol type, and the requested service name starts with that prefix.
		fmt.Sprintf(`allow if %s($type, $name), %s($type, $prefix), $name.starts_with($prefix)`, FactService, FactGrantedServicePrefix),

		// Suffix Match: Allows access if the token possesses a granted_service_suffix fact
		// for the given protocol type, and the requested service name ends with that suffix.
		fmt.Sprintf(`allow if %s($type, $name), %s($type, $suffix), $name.ends_with($suffix)`, FactService, FactGrantedServiceSuffix),

		// Type Wildcard: Allows access if the token possesses a granted_service_all fact
		// for the given protocol type, granting access to ANY service name within that namespace.
		fmt.Sprintf(`allow if %s($type, $name), %s($type)`, FactService, FactGrantedServiceAll),

		// Global Wildcard: Allows access if the token possesses a granted_service_all_types fact,
		// granting access to literally any service in any namespace (equivalent to '*').
		fmt.Sprintf(`allow if %s($type, $name), %s()`, FactService, FactGrantedServiceAllTypes),
	}

	for i, pStr := range policyStrs {
		p, err := parser.FromStringPolicy(pStr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse baseline policy %d: %v", i, err))
		}
		BaselinePolicies = append(BaselinePolicies, p)
	}

	// 2. Target Evaluation Rules
	// These rules satisfy the check if allow_network_target($fact, $val) injected by the control plane.
	ruleStrs := []string{
		// Exact Match: Derives allow_network_target if the token has a granted_target_exact fact matching a target_fact exactly.
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s($fact, $val)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetExact),

		// Exact Set Match: Derives allow_network_target if the token has a granted_target_set fact for the
		// given fact name whose Set of values contains the target_fact value.
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s($fact, $set), $set.contains($val)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetSet),

		// Prefix Match: Derives allow_network_target if the token has a granted_target_prefix fact and the target_fact value starts with that prefix.
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s($fact, $prefix), $val.starts_with($prefix)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetPrefix),

		// Suffix Match: Derives allow_network_target if the token has a granted_target_suffix fact and the target_fact value ends with that suffix.
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s($fact, $suffix), $val.ends_with($suffix)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetSuffix),

		// Wildcard Fact Match: Derives allow_network_target if the token has a granted_target_all fact for a specific fact name (e.g. all values for "group").
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s($fact)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetAll),

		// Global Wildcard Match: Derives allow_network_target if the token has a granted_target_all_facts fact, unconditionally allowing any target_fact.
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

	// BaselineReplayCheck prevents token theft/replay by ensuring the client_peer_id fact (embedded by the control plane during issuance)
	// perfectly matches the connection_peer_id fact (provided by the local node verifying the incoming libp2p connection).
	BaselineReplayCheck, err = parser.FromStringCheck(fmt.Sprintf(`check if %s($id), %s($id)`, FactClientPeerID, FactConnectionPeerID))
	if err != nil {
		panic(fmt.Sprintf("failed to parse replay check: %v", err))
	}

	// BaselineTargetCheck enforces network target restrictions. The token must either have an unrestricted target,
	// or one of the Target Evaluation Rules must have successfully derived an allow_network_target fact.
	BaselineTargetCheck, err = parser.FromStringCheck(fmt.Sprintf(`check if %s($fact, $val) or %s()`, FactAllowNetworkTarget, FactTargetUnrestricted))
	if err != nil {
		panic(fmt.Sprintf("failed to parse target check: %v", err))
	}

	// OIDC Claims to Target Facts: Maps dynamically generated OIDC facts (like `user("alice")`)
	// into standard `target_fact("user", "alice")` facts for unified evaluation against network target policies.
	for _, val := range OIDCClaimToFact() {
		ruleStr := fmt.Sprintf(`%s(%q, $val) <- %s($val)`, FactTargetFact, val, val)
		r, err := parser.FromStringRule(ruleStr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse target fact rule: %v", err))
		}
		TargetFactRules = append(TargetFactRules, r)
	}

	// Node PeerID Target Fact: Ensures the target node's PeerID is also evaluated as a standard target_fact.
	r, err := parser.FromStringRule(fmt.Sprintf(`%s(%q, $val) <- %s($val)`, FactTargetFact, FactNode, FactNode))
	if err != nil {
		panic(fmt.Sprintf("failed to parse node fact rule: %v", err))
	}
	TargetFactRules = append(TargetFactRules, r)

	// ControlPlaneStaticTimeCheck ensures the token is not expired at the time of evaluation.
	ControlPlaneStaticTimeCheck, err = parser.FromStringCheck(fmt.Sprintf(`check if %s($time), %s($exp), $time <= $exp`, FactTime, FactExpiration))
	if err != nil {
		panic(fmt.Sprintf("failed to parse static time check: %v", err))
	}

	// AllowIfTruePolicy is a permissive fallback policy used when explicit local node policies are omitted.
	// Note that this does NOT mean all requests are automatically allowed. Biscuit requires at least one policy
	// to evaluate to true AND all checks to pass. This simply satisfies the policy requirement, effectively
	// deferring entirely to the control plane's checks and granted facts without imposing extra local restrictions.
	AllowIfTruePolicy, err = parser.FromStringPolicy("allow if true")
	if err != nil {
		panic(fmt.Sprintf("failed to parse static allow policy: %v", err))
	}
}

// BuildServiceDatalogFact translates a service pattern string into a Datalog Fact.
func BuildServiceDatalogFact(serviceStr string) biscuit.Fact {
	svcType, svcName := ParseServiceTarget(serviceStr)
	if svcType == "*" && svcName == "*" {
		return biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedServiceAllTypes,
			IDs:  []biscuit.Term{},
		}}
	} else if svcName == "*" {
		return biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedServiceAll,
			IDs:  []biscuit.Term{biscuit.String(svcType)},
		}}
	} else if strings.HasPrefix(svcName, "*.") {
		return biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedServiceSuffix,
			IDs:  []biscuit.Term{biscuit.String(svcType), biscuit.String(svcName[1:])},
		}}
	} else if strings.HasSuffix(svcName, ".*") {
		return biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedServicePrefix,
			IDs:  []biscuit.Term{biscuit.String(svcType), biscuit.String(svcName[:len(svcName)-1])},
		}}
	}
	return biscuit.Fact{Predicate: biscuit.Predicate{
		Name: FactGrantedServiceExact,
		IDs:  []biscuit.Term{biscuit.String(svcType), biscuit.String(svcName)},
	}}
}

// BuildTargetDatalogFact translates a target pattern string into a Datalog Fact.
func BuildTargetDatalogFact(targetStr string) biscuit.Fact {
	tFact, tVal := ParseServiceTarget(targetStr)
	if tFact == "" {
		tFact = "node"
	}
	if tFact == "*" && tVal == "*" {
		return biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedTargetAllFacts,
			IDs:  []biscuit.Term{},
		}}
	} else if tVal == "*" {
		return biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedTargetAll,
			IDs:  []biscuit.Term{biscuit.String(tFact)},
		}}
	} else if strings.HasPrefix(tVal, "*.") {
		return biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedTargetSuffix,
			IDs:  []biscuit.Term{biscuit.String(tFact), biscuit.String(tVal[1:])},
		}}
	} else if strings.HasSuffix(tVal, ".*") {
		return biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedTargetPrefix,
			IDs:  []biscuit.Term{biscuit.String(tFact), biscuit.String(tVal[:len(tVal)-1])},
		}}
	}
	return biscuit.Fact{Predicate: biscuit.Predicate{
		Name: FactGrantedTargetExact,
		IDs:  []biscuit.Term{biscuit.String(tFact), biscuit.String(tVal)},
	}}
}

// LabelFacts materializes a label set as one Datalog fact per key=value
// pair (see FactLabel). Keys are sorted for deterministic fact ordering. An
// empty set returns nil.
func LabelFacts(labels map[string]string) []biscuit.Fact {
	if len(labels) == 0 {
		return nil
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	facts := make([]biscuit.Fact, 0, len(labels))
	for _, k := range keys {
		facts = append(facts, biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactLabel,
			IDs:  []biscuit.Term{biscuit.String(k), biscuit.String(labels[k])},
		}})
	}
	return facts
}

// LabelCheck compiles a required label set (canonical, pre-validated with
// ValidateLabels) into a single fail-closed check satisfied when the token
// carries any of them: `check if label("region", "us-east-1") or
// label("team", "platform")`.
func LabelCheck(required map[string]string) (biscuit.Check, error) {
	if len(required) == 0 {
		return biscuit.Check{}, fmt.Errorf("no required labels")
	}
	keys := make([]string, 0, len(required))
	for k := range required {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	clauses := make([]string, 0, len(required))
	for _, k := range keys {
		if err := ValidateLabelKey(k); err != nil {
			return biscuit.Check{}, err
		}
		v := required[k]
		if err := ValidateLabelValue(v); err != nil {
			return biscuit.Check{}, err
		}
		clauses = append(clauses, fmt.Sprintf("%s(%q, %q)", FactLabel, k, v))
	}
	return parser.FromStringCheck("check if " + strings.Join(clauses, " or "))
}

// isExactService reports whether serviceStr resolves to a plain exact-match grant, as opposed to a
// wildcard/prefix/suffix pattern which already collapses to a single, cheap fact via BuildServiceDatalogFact.
func isExactService(serviceStr string) (svcType, svcName string, exact bool) {
	svcType, svcName = ParseServiceTarget(serviceStr)
	if svcType == "*" && svcName == "*" {
		return svcType, svcName, false
	}
	if svcName == "*" || strings.HasPrefix(svcName, "*.") || strings.HasSuffix(svcName, ".*") {
		return svcType, svcName, false
	}
	return svcType, svcName, true
}

// isExactTarget reports whether targetStr resolves to a plain exact-match grant, as opposed to a
// wildcard/prefix/suffix pattern which already collapses to a single, cheap fact via BuildTargetDatalogFact.
func isExactTarget(targetStr string) (tFact, tVal string, exact bool) {
	tFact, tVal = ParseServiceTarget(targetStr)
	if tFact == "" {
		tFact = "node"
	}
	if tFact == "*" && tVal == "*" {
		return tFact, tVal, false
	}
	if tVal == "*" || strings.HasPrefix(tVal, "*.") || strings.HasSuffix(tVal, ".*") {
		return tFact, tVal, false
	}
	return tFact, tVal, true
}

// BuildServiceDatalogFacts translates a list of service patterns into a minimal set of Datalog facts.
// Exact-match entries are grouped by service type into a single granted_service_set fact each, so
// token/world fact counts stay flat regardless of how many exact services a role grants. Wildcard,
// prefix and suffix entries keep their existing one-fact-per-entry representation via
// BuildServiceDatalogFact, since those already collapse to a single fact per entry.
func BuildServiceDatalogFacts(services []string) []biscuit.Fact {
	facts := make([]biscuit.Fact, 0, len(services))
	exactByType := make(map[string]map[string]bool)
	var types []string
	for _, svc := range services {
		svcType, svcName, exact := isExactService(svc)
		if !exact {
			facts = append(facts, BuildServiceDatalogFact(svc))
			continue
		}
		if _, ok := exactByType[svcType]; !ok {
			exactByType[svcType] = make(map[string]bool)
			types = append(types, svcType)
		}
		exactByType[svcType][svcName] = true
	}
	sort.Strings(types)
	for _, svcType := range types {
		names := make([]string, 0, len(exactByType[svcType]))
		for name := range exactByType[svcType] {
			names = append(names, name)
		}
		sort.Strings(names)
		bset := make(biscuit.Set, 0, len(names))
		for _, name := range names {
			bset = append(bset, biscuit.String(name))
		}
		facts = append(facts, biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedServiceSet,
			IDs:  []biscuit.Term{biscuit.String(svcType), bset},
		}})
	}
	return facts
}

// BuildTargetDatalogFacts translates a list of target patterns into a minimal set of Datalog facts.
// Exact-match entries are grouped by fact name into a single granted_target_set fact each, so
// token/world fact counts stay flat regardless of how many exact targets a role grants. Wildcard,
// prefix and suffix entries keep their existing one-fact-per-entry representation via
// BuildTargetDatalogFact, since those already collapse to a single fact per entry.
func BuildTargetDatalogFacts(targets []string) []biscuit.Fact {
	facts := make([]biscuit.Fact, 0, len(targets))
	exactByFact := make(map[string]map[string]bool)
	var factNames []string
	for _, t := range targets {
		tFact, tVal, exact := isExactTarget(t)
		if !exact {
			facts = append(facts, BuildTargetDatalogFact(t))
			continue
		}
		if _, ok := exactByFact[tFact]; !ok {
			exactByFact[tFact] = make(map[string]bool)
			factNames = append(factNames, tFact)
		}
		exactByFact[tFact][tVal] = true
	}
	sort.Strings(factNames)
	for _, tFact := range factNames {
		vals := make([]string, 0, len(exactByFact[tFact]))
		for val := range exactByFact[tFact] {
			vals = append(vals, val)
		}
		sort.Strings(vals)
		bset := make(biscuit.Set, 0, len(vals))
		for _, val := range vals {
			bset = append(bset, biscuit.String(val))
		}
		facts = append(facts, biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedTargetSet,
			IDs:  []biscuit.Term{biscuit.String(tFact), bset},
		}})
	}
	return facts
}
