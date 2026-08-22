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
	"fmt"
	"strings"

	"github.com/google/sam/api"
)

// Routing decides where a flow leaving a sandbox belongs, from the destination
// name alone. It is deliberately free of I/O so the decision can be tested
// exhaustively and read in one sitting: opening the connection is a separate
// concern.

// RouteKind is the destination class a flow was resolved to.
type RouteKind int

const (
	// RouteMeshEntrypoint is the gateway's own agent-facing surface: the mesh
	// services an agent may consume, with the provider chosen by policy. It is
	// not the node's sidecar API, which an agent never reaches.
	RouteMeshEntrypoint RouteKind = iota

	// RouteMeshService is a service provided by some peer in the mesh. Which
	// peer is a discovery decision, deliberately not encoded in the name.
	RouteMeshService

	// RouteExternal is a destination outside the mesh, permitted by policy.
	RouteExternal
)

func (k RouteKind) String() string {
	switch k {
	case RouteMeshEntrypoint:
		return "mesh-entrypoint"
	case RouteMeshService:
		return "mesh-service"
	case RouteExternal:
		return "external"
	default:
		return fmt.Sprintf("RouteKind(%d)", int(k))
	}
}

// Route is the outcome of classifying a destination.
type Route struct {
	Kind RouteKind

	// ServiceURI is the canonical mesh identity for RouteMeshService, e.g.
	// "inference://openrouter". It is the same string policy is written
	// against, so a routing decision and an authorization decision can never
	// disagree about what was asked for.
	ServiceURI string

	Destination Destination
}

// EgressPolicy is the allowlist for destinations outside the mesh. A nil
// policy allows nothing: a sandbox with no configured egress must reach
// nothing, so the zero value has to be the safe one.
type EgressPolicy struct {
	exact    map[string]struct{}
	suffixes []string
}

// NewEgressPolicy compiles an allowlist. Entries are either an exact host
// ("api.github.com") or a leading-label wildcard ("*.pypi.org"). Any other use
// of "*" is rejected rather than quietly treated as a literal, because an
// allowlist entry that silently means something other than what it looks like
// is how allowlists leak.
func NewEgressPolicy(allow []string) (*EgressPolicy, error) {
	p := &EgressPolicy{exact: make(map[string]struct{}, len(allow))}
	for _, raw := range allow {
		entry := api.NormalizeMeshHost(raw)
		if entry == "" {
			return nil, fmt.Errorf("empty egress allow entry")
		}
		if suffix, found := strings.CutPrefix(entry, "*."); found {
			if suffix == "" || strings.Contains(suffix, "*") {
				return nil, fmt.Errorf("invalid egress allow entry %q", raw)
			}
			// Stored with the dot so matching is anchored on a label boundary.
			p.suffixes = append(p.suffixes, "."+suffix)
			continue
		}
		if strings.Contains(entry, "*") {
			return nil, fmt.Errorf("invalid egress allow entry %q: a wildcard is only allowed as a leading %q label", raw, "*.")
		}
		p.exact[entry] = struct{}{}
	}
	return p, nil
}

// Allows reports whether host may be reached. A wildcard covers subdomains
// only, never the parent, matching how every other wildcard in this system and
// in TLS behaves.
func (p *EgressPolicy) Allows(host string) bool {
	if p == nil {
		return false
	}
	h := api.NormalizeMeshHost(host)
	if h == "" {
		return false
	}
	if _, ok := p.exact[h]; ok {
		return true
	}
	for _, suffix := range p.suffixes {
		if strings.HasSuffix(h, suffix) && len(h) > len(suffix) {
			return true
		}
	}
	return false
}

// Router classifies destinations arriving on the sandbox boundary.
type Router struct {
	// Egress is the allowlist for destinations outside the mesh. Nil denies
	// every external destination.
	Egress *EgressPolicy
}

// Route classifies a destination, or returns ErrNotAllowed. Mesh names that do
// not name a service are denied rather than reported as unreachable: to a
// sandbox, "not permitted" and "does not exist" must look the same, or the
// boundary becomes a discovery oracle for the mesh's contents.
func (r *Router) Route(dst Destination) (Route, error) {
	if api.IsMeshEntrypointHost(dst.Name) {
		return Route{Kind: RouteMeshEntrypoint, Destination: dst}, nil
	}

	if api.IsMeshHost(dst.Name) {
		serviceURI, err := api.ParseMeshHost(dst.Name)
		if err != nil {
			return Route{}, fmt.Errorf("%w: %s names no mesh service", ErrNotAllowed, dst.Name)
		}
		return Route{Kind: RouteMeshService, ServiceURI: serviceURI, Destination: dst}, nil
	}

	// Literal addresses are not special-cased: they carry no name, so they are
	// allowed only by an exact entry. CIDR ranges are deliberately not
	// supported yet; adding them is a policy-language decision, not a routing
	// one.
	if !r.Egress.Allows(dst.Name) {
		return Route{}, fmt.Errorf("%w: %s", ErrNotAllowed, dst.Name)
	}
	return Route{Kind: RouteExternal, Destination: dst}, nil
}
