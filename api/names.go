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
	"strings"
)

// ============================================================================
// Sandbox Mesh Names
// ============================================================================
//
// Agents run inside sandboxes (Firecracker microVMs, network=none containers)
// and reach the mesh by connecting to a *name*, exactly as they would reach the
// public internet. This file defines the one projection of the mesh service
// namespace into DNS-shaped names, so that a hostname seen on the sandbox
// boundary and a service URI seen by the policy engine are the same identity
// written two ways:
//
//	inference://openrouter   <->   openrouter.inference.sam.alt
//	mcp://code-reviewer      <->   code-reviewer.mcp.sam.alt
//
// The URI form (see MCPServicePrefix / InferenceServicePrefix in network.go) is
// canonical: it is what the control plane authorizes in allowed_services and
// what lands in the Biscuit service() fact. The hostname form exists only so
// unmodified agents can use an unmodified HTTP client. Never introduce a
// routing decision that can be expressed in one form but not the other.

const (
	// MeshZone is the DNS suffix under which mesh services are addressed from
	// inside a sandbox.
	//
	// ".alt" is the pseudo-top-level domain reserved by RFC 9476 for namespaces
	// that are explicitly NOT resolved through the DNS. That is precisely this
	// case: these names are resolved by the mesh (service discovery over
	// libp2p), never by a resolver. Using it guarantees the zone can never
	// collide with a delegated gTLD, and guarantees a name that leaks out of a
	// sandbox fails closed instead of resolving to somebody else's host.
	MeshZone = "sam.alt"

	// MeshEntrypointHost is the reserved name an agent uses to reach the mesh
	// services its gateway offers it: inference and tools, with the provider
	// chosen by policy.
	//
	// It deliberately does not name the node. A sam-node's sidecar API is a
	// local, operator-facing surface — it can register services, drive the raw
	// egress proxy and read node internals — and an agent has no business
	// reaching any of it. The gateway consumes the node; the agent consumes the
	// mesh through the gateway, and the two must not be the same address.
	MeshEntrypointHost = "mesh." + MeshZone
)

// meshZoneSuffix is the dotted form used for suffix matching.
const meshZoneSuffix = "." + MeshZone

// NormalizeMeshHost canonicalizes a hostname taken off the sandbox boundary: it
// drops a trailing root dot and lowercases the name. DNS names are
// case-insensitive, so a mesh name only ever addresses a lowercase service
// name; services registered with uppercase characters are reachable by URI but
// not by hostname.
func NormalizeMeshHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// IsMeshHost reports whether host falls inside the mesh zone. It does not
// validate the name beyond the suffix: use ParseMeshHost for that.
func IsMeshHost(host string) bool {
	h := NormalizeMeshHost(host)
	return h == MeshZone || strings.HasSuffix(h, meshZoneSuffix)
}

// IsMeshEntrypointHost reports whether host addresses the gateway's own
// agent-facing surface.
func IsMeshEntrypointHost(host string) bool {
	return NormalizeMeshHost(host) == MeshEntrypointHost
}

// ParseMeshHost translates a mesh hostname into its canonical service URI.
//
//	openrouter.inference.sam.alt -> inference://openrouter
//	code-reviewer.mcp.sam.alt    -> mcp://code-reviewer
//
// The service type is the label immediately left of the zone; everything to its
// left is the service name, which may itself contain dots (service names are
// validated as DNS names, not as single labels). MeshEntrypointHost is not a
// service and is rejected here; callers must test it with IsMeshEntrypointHost
// first.
//
// Names are not resolved to a provider: which peer serves the returned URI is a
// discovery decision, and deliberately not encoded in the name. If pinning to
// one provider is ever needed, the natural extension is a longer form carrying
// the peer — mirroring the internal libp2p://<peer>/<type>/<name> URL — but it
// requires settling on a DNS-safe peer encoding first, because a base58 peer ID
// is case-sensitive and DNS labels are not (IPFS solves the same problem in
// subdomain gateways by using lowercase base36 CIDs).
func ParseMeshHost(host string) (serviceURI string, err error) {
	h := NormalizeMeshHost(host)
	if h == "" {
		return "", fmt.Errorf("empty mesh host")
	}
	// A hostname carries neither a port nor a path: stripping those is the
	// caller's job, and anything else here means a malformed request that must
	// fail closed rather than be coerced into a service URI.
	if strings.ContainsAny(h, ":/") {
		return "", fmt.Errorf("mesh host %q must not contain a port or a path", host)
	}
	if h == MeshEntrypointHost {
		return "", fmt.Errorf("%q is the gateway entrypoint, not a mesh service", host)
	}
	rest, found := strings.CutSuffix(h, meshZoneSuffix)
	if !found || rest == "" {
		return "", fmt.Errorf("host %q is not in the mesh zone %q", host, MeshZone)
	}

	dot := strings.LastIndex(rest, ".")
	if dot <= 0 || dot == len(rest)-1 {
		return "", fmt.Errorf("mesh host %q must be <service>.<type>.%s", host, MeshZone)
	}
	name, typeStr := rest[:dot], rest[dot+1:]

	if _, err := ParseServiceType(typeStr); err != nil {
		return "", fmt.Errorf("mesh host %q: %w", host, err)
	}

	uri := typeStr + "://" + name
	if err := ValidateServiceFormat(uri); err != nil {
		return "", fmt.Errorf("mesh host %q: %w", host, err)
	}
	return uri, nil
}

// MeshHost is the inverse of ParseMeshHost: it renders the hostname a sandboxed
// agent should connect to in order to reach the given service.
func MeshHost(t ServiceType, serviceName string) (string, error) {
	typeStr, err := ServiceTypeToString(t)
	if err != nil {
		return "", err
	}
	if serviceName == "" {
		return "", fmt.Errorf("service name cannot be empty")
	}
	if serviceName != NormalizeMeshHost(serviceName) {
		return "", fmt.Errorf("service name %q is not addressable as a mesh host: it must be lowercase", serviceName)
	}
	host := serviceName + "." + typeStr + meshZoneSuffix
	if _, err := ParseMeshHost(host); err != nil {
		return "", err
	}
	return host, nil
}
