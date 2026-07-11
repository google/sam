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
	"regexp"
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
// SAM Custom HTTP Headers
// ============================================================================

const (
	// HeaderSamBiscuit is the custom HTTP header used to carry the base64-encoded
	// Biscuit token containing the node's identity credentials when forwarding requests
	// over libp2p HTTP between nodes in the mesh.
	//
	// This header is internal to the SAM mesh datapath and is stripped before requests
	// are forwarded to backend services.
	HeaderSamBiscuit = "X-Sam-Biscuit"

	// HeaderSamAuthorization is the custom HTTP header that a client can pass to a local
	// SAM node's egress proxy to supply the Authorization header intended for the remote service.
	//
	// The egress proxy uses "Authorization: Bearer <token>" for its own local authentication.
	// By specifying the target service's auth token in HeaderSamAuthorization, the client avoids
	// stomping local authentication, and prevents the egress proxy from leaking the local sidecar
	// authentication token to the remote peer. The egress proxy maps this header back to
	// "Authorization" before transmitting the request to the destination node.
	HeaderSamAuthorization = "X-Sam-Authorization"

	// HeaderSamNoTrailingSlash is the custom HTTP header set by the ingress handler
	// to indicate that the original request had no trailing slash.
	//
	// This helps backward-compatibility with services that strictly distinguish
	// between a root path "/" and an empty path "".
	HeaderSamNoTrailingSlash = "X-Sam-No-Trailing-Slash"
)

// ============================================================================
// Service Classification & Namespaces
// ============================================================================

const (
	// SystemNamespace is the namespace reserved for built-in mesh services and protocols.
	SystemNamespace = "sam:system"

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

var (
	// rfc3986URIRegex is the exact regular expression provided by RFC 3986 Appendix B
	// for breaking down a well-formed URI reference into its components.
	// Reference: https://tools.ietf.org/html/rfc3986#appendix-B
	//
	// Breaking down the regex:
	//   ^(([^:/?#]+):)?   - Group 1 & 2: Scheme (optional, e.g. "mcp:")
	//   (//([^/?#]*))?    - Group 3 & 4: Authority (optional, e.g. "//my-service")
	//   ([^?#]*)          - Group 5: Path
	//   (\?([^#]*))?      - Group 6 & 7: Query (optional)
	//   (#(.*))?          - Group 8 & 9: Fragment (optional)
	rfc3986URIRegex = regexp.MustCompile(`^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?`)

	// dnsNameRegex is adapted from govalidator's DNSName pattern.
	// Reference: https://github.com/asaskevich/govalidator/blob/3dd3875e2b081a20d6eed935913a482fea14ecd0/patterns.go#L29
	// It is adapted to allow underscores and asterisks (wildcards).
	// The asterisk '*' can only be at the very beginning (e.g., "*.example.com") or at the very end (e.g., "example.*").
	dnsNameRegex = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(\.[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62})*(\.\*)?[\._]?$`)
)

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

	if strings.Contains(target, "://") {
		matches := rfc3986URIRegex.FindStringSubmatch(target)
		if len(matches) < 6 {
			return "", target
		}
		scheme := matches[2]
		hasAuthority := matches[3] != ""
		authority := matches[4]
		path := matches[5]

		if scheme == "" || !hasAuthority {
			return "", target
		}
		name := authority
		if path != "" {
			name = authority + path
		}
		return scheme, name
	}

	parts := strings.SplitN(target, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", target
}

// SplitToolName splits a fully qualified MCP tool name into its target service URI
// and the original tool name.
//
// Expected format: "scheme://service/tool" (e.g., "mcp://my-service/my-tool").
// If the input is empty or invalid, it returns an error. No default fallback is applied.
func SplitToolName(toolName string) (targetService, originalToolName string, err error) {
	if toolName == "" {
		return "", "", fmt.Errorf("tool name cannot be empty")
	}

	matches := rfc3986URIRegex.FindStringSubmatch(toolName)
	if len(matches) < 6 {
		return "", "", fmt.Errorf("invalid namespaced tool name %q: must follow explicit URI format 'scheme://service/tool'", toolName)
	}

	scheme := matches[2]
	hasAuthority := matches[3] != ""
	authority := matches[4]
	path := matches[5]

	if scheme == "" || !hasAuthority || authority == "" || path == "" || path == "/" {
		return "", "", fmt.Errorf("invalid namespaced tool name %q: must follow explicit URI format 'scheme://service/tool'", toolName)
	}

	// Reject query parameters or fragments in the tool name
	if matches[6] != "" || matches[8] != "" {
		return "", "", fmt.Errorf("invalid namespaced tool name %q: queries and fragments are not allowed", toolName)
	}

	targetService = scheme + "://" + authority
	originalToolName = strings.TrimPrefix(path, "/")
	return targetService, originalToolName, nil
}
