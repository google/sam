package api

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/asaskevich/govalidator"
)

// ValidateServiceFormat ensures the service string follows the explicit URI format.
func ValidateServiceFormat(svc string) error {
	if svc == "*" {
		return nil
	}
	// We parse the service string as a URL to enforce hierarchical URIs (e.g., mcp://name).
	// - If no scheme is present (e.g., "mcp-service"), u.Scheme will be empty.
	// - If a legacy non-hierarchical format is used (e.g., "mcp:my-service"), url.Parse will parse the
	//   part after the colon into u.Opaque. We reject u.Opaque != "" to ensure that the hierarchical
	//   separator "://" is explicitly present (which maps the target name to u.Host instead of u.Opaque).
	//   Without this check, "mcp:my-service.local" would parse successfully and be accepted since
	//   "my-service.local" is a valid DNS name.
	u, err := url.Parse(svc)
	if err != nil || u.Scheme == "" || u.Opaque != "" {
		return fmt.Errorf("invalid service format %q: must follow explicit URI format (e.g., mcp://name)", svc)
	}
	if u.User != nil {
		return fmt.Errorf("invalid service format %q: userinfo is not allowed in service URIs", svc)
	}
	typ, val := ParseServiceTarget(svc)
	if typ == "" {
		return fmt.Errorf("invalid service format %q: type cannot be empty", svc)
	}
	if val == "" {
		return fmt.Errorf("invalid service format %q: value cannot be empty", svc)
	}

	if val == "*" {
		return nil
	}

	// Split val into host and path (if any)
	parts := strings.SplitN(val, "/", 2)
	host := parts[0]

	// Host validation
	if strings.Contains(host, "_") {
		return fmt.Errorf("invalid service format %q: host cannot contain underscores", svc)
	}

	// Normalize wildcards for DNS validation.
	// Note: We only support prefix wildcards starting with "*." (e.g., "*.service")
	// and suffix wildcards ending with ".*" (e.g., "service.*"). Both formats
	// strictly require a dot separator at the domain boundary.
	// Arbitrary partial matching (e.g., "dev-*", "*-prod", or "service*") is not
	// supported because the unnormalized "*" character will fail the DNS validation.
	h := host
	if strings.HasPrefix(h, "*.") {
		h = "wildcard." + h[2:]
	}
	if strings.HasSuffix(h, ".*") {
		h = h[:len(h)-2] + ".wildcard"
	}

	if !govalidator.IsDNSName(h) {
		return fmt.Errorf("invalid service format %q: %q is not a valid DNS name", svc, host)
	}

	return nil
}

// ValidateTargetFormat ensures the target string follows the explicit fact:value format.
func ValidateTargetFormat(target string) error {
	if target == "*" {
		return nil
	}
	parts := strings.SplitN(target, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid target format %q: must be fact:value (e.g., group:backend)", target)
	}
	fact, val := parts[0], parts[1]
	if fact == "" {
		return fmt.Errorf("invalid target format %q: fact cannot be empty", target)
	}
	if val == "" {
		return fmt.Errorf("invalid target format %q: value cannot be empty", target)
	}
	return nil
}
