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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

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

	// GossipControlPlaneSync is the GossipSub topic used by the control plane to sync cluster state.
	GossipControlPlaneSync = "/sam/control-plane/sync/v1"

	// DiscoveryTopicPrefix is the GossipSub topic namespace for interest-scoped
	// service announcements (ServiceAnnounce messages). Full topics are built
	// with DiscoveryTopic; the version segment allows wire evolution.
	DiscoveryTopicPrefix = "/sam/discovery/v1"

	// DefaultAudience is the default audience string used in OIDC token validation.
	DefaultAudience = "sam-mesh-audience"
)

// ============================================================================
// Token Lifespans & Session Constants
// ============================================================================

const (
	// BiscuitTokenTTL is the strict cryptographically enforced lifespan
	// of a minted Biscuit token (24 hours).
	// This is verified locally by each peer on every connection.
	BiscuitTokenTTL = 24 * time.Hour

	// OIDCSessionTTL is the maximum database-enforced lifespan of a node's OIDC
	// interactive enrollment session (90 days). After this period, the node
	// must re-authenticate with the OIDC provider to establish a new session.
	OIDCSessionTTL = 90 * 24 * time.Hour

	// TokenRefreshCheckInterval is the frequency at which the node daemon and router check
	// if their current Biscuit token is close to expiration and needs to be proactively refreshed.
	TokenRefreshCheckInterval = 10 * time.Minute
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

	// HeaderSamAgent names the agent a request is made on behalf of, as a
	// canonical agent identifier (see api/agent.go). It is set by the sandbox
	// gateway on the node's local API socket, and honoured by the node only
	// there: arriving on that socket is proof the caller is the gateway, which
	// is the only party that knows which agent a flow belongs to.
	//
	// A sandboxed agent can never set it. The gateway overwrites the header on
	// every request it forwards, so a value an agent supplies is replaced by
	// the identity the platform bound to its channel, never merged with it.
	HeaderSamAgent = "X-Sam-Agent"

	// HeaderSamAuthentication is the custom HTTP header used to authenticate a local
	// process to this node's sidecar API (the shared secret configured via
	// "--api-token-path" or the SAM_API_TOKEN environment variable). Using a
	// SAM-specific header name — instead of the standard
	// "Authorization" header — leaves "Authorization" free to always mean what
	// every HTTP client expects: the credential for the destination being called.
	// The sidecar strips this header before forwarding any request off-node, so
	// it never leaks to a remote peer or backend service.
	//
	// For compatibility with MCP clients that only support a plain "Authorization"
	// header, purely-local endpoints (that never forward it anywhere) also accept
	// "Authorization" as an alias. The egress/inference proxy does NOT: there,
	// "Authorization" is reserved exclusively for the destination's credential.
	HeaderSamAuthentication = "X-Sam-Authentication"

	// HeaderSamNoTrailingSlash is the custom HTTP header set by the ingress handler
	// to indicate that the original request had no trailing slash.
	//
	// This helps backward-compatibility with services that strictly distinguish
	// between a root path "/" and an empty path "".
	HeaderSamNoTrailingSlash = "X-Sam-No-Trailing-Slash"

	// HeaderSamRequiredLabels constrains an inference request on the sidecar's
	// OpenAI-compatible endpoints (/v1/*) to providers attested with any of a
	// comma-separated list of "key=value" label requirements (see
	// api/labels.go and LabelCheck); invalid entries are rejected with HTTP
	// 400. It can only narrow what mesh policy allows, never widen it. Absent
	// means any provider permitted by policy.
	//
	// Reserved as part of the sidecar contract; enforced by the provider
	// scorer. Label declarations are routing hints until attested via the
	// node's Biscuit (see api/labels.go).
	HeaderSamRequiredLabels = "X-Sam-Required-Labels"
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

// DiscoveryTopic returns the GossipSub topic for announcements about one
// routing key (a model ID for inference, a tool name for MCP). Keys are
// hashed so topic names stay bounded; consumers match exact keys from the
// ServiceAnnounce payload, so hash collisions only merge announcement
// streams, never routing decisions.
func DiscoveryTopic(t ServiceType, key string) (string, error) {
	typeStr, err := ServiceTypeToString(t)
	if err != nil {
		return "", err
	}
	if key == "" {
		return "", fmt.Errorf("discovery topic key cannot be empty")
	}
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s/%s/%s", DiscoveryTopicPrefix, typeStr, hex.EncodeToString(sum[:8])), nil
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
