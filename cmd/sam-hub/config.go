package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/google/sam/api"
	"gopkg.in/yaml.v2"
)

// LoadPolicyConfig loads the policy configuration from the specified path.
// If the file is missing, it returns an empty initialized config.
func LoadPolicyConfig(path string) (*api.PolicyConfig, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &api.PolicyConfig{
			Version:  "v1alpha1",
			Bindings: []api.Binding{},
			Roles:    make(map[string]api.RolePolicy),
		}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config api.PolicyConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	for role, rolePolicy := range config.Roles {
		for _, customFact := range rolePolicy.CustomDatalog {
			trimmed := strings.TrimRight(strings.TrimSpace(customFact), ";")
			_, err := parser.FromStringFact(trimmed)
			if err != nil {
				return nil, fmt.Errorf("invalid custom datalog fact for role %q: %w", role, err)
			}
		}
	}

	if err := ValidatePolicyConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// ValidatePolicyConfig ensures that no wildcards are used in policies, and that all referenced roles in bindings exist.
func ValidatePolicyConfig(config *api.PolicyConfig) error {
	for _, b := range config.Bindings {
		if len(b.Members) == 0 {
			return fmt.Errorf("binding must specify at least one member")
		}

		for _, member := range b.Members {
			if member == api.SystemAuthenticated {
				continue
			}
			parts := strings.SplitN(member, ":", 2)
			if len(parts) != 2 {
				return fmt.Errorf("member %q is invalid, must be in format 'type:value' or '%s'", member, api.SystemAuthenticated)
			}
			prefix := parts[0]
			if _, validPrefix := api.ValidMemberPrefixes[prefix]; !validPrefix {
				return fmt.Errorf("member prefix %q is invalid, expected one of the standard identity facts (e.g., user, group, email, node)", prefix)
			}
		}

		if b.Role == "" {
			return fmt.Errorf("binding role cannot be empty")
		}
		if _, exists := config.Roles[b.Role]; !exists {
			return fmt.Errorf("binding role %q does not exist in defined roles", b.Role)
		}
	}

	for role, rolePolicy := range config.Roles {
		for _, svc := range rolePolicy.AllowedServices {
			if err := api.ValidateServiceFormat(svc); err != nil {
				return fmt.Errorf("invalid allowed service in role %q: %w", role, err)
			}
		}
		for _, target := range rolePolicy.AllowedTargets {
			if err := api.ValidateTargetFormat(target); err != nil {
				return fmt.Errorf("invalid allowed target in role %q: %w", role, err)
			}
		}
	}
	return nil
}
