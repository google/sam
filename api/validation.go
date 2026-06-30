package api

import (
	"fmt"
	"regexp"
	"strings"
)

// The value can be a domain label, allowing prefix/suffix wildcards (e.g. *.foo.bar or foo.*)
var domainLabelRegex = regexp.MustCompile(`^(?:\*\.)?(?:[a-zA-Z0-9-]+\.)*(?:[a-zA-Z0-9-]+)(?:\.\*)?$|^\*$`)

// ValidateServiceFormat ensures the service string follows the explicit type:value format.
func ValidateServiceFormat(svc string) error {
	parts := strings.SplitN(svc, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid service format %q: must be type:value (e.g., mcp:foo)", svc)
	}
	typ, val := parts[0], parts[1]
	if typ == "" {
		return fmt.Errorf("invalid service format %q: type cannot be empty", svc)
	}
	if val == "" {
		return fmt.Errorf("invalid service format %q: value cannot be empty", svc)
	}
	if !domainLabelRegex.MatchString(val) {
		return fmt.Errorf("invalid service format %q: value must be a valid domain label with optional prefix/suffix wildcard", svc)
	}
	return nil
}

// ValidateTargetFormat ensures the target string follows the explicit fact:value format.
func ValidateTargetFormat(target string) error {
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
