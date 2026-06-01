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
		if b.Group == "" && b.User == "" {
			return fmt.Errorf("binding must specify either 'group' or 'user'")
		}
		if b.Group != "" && b.User != "" {
			return fmt.Errorf("binding cannot specify both 'group' and 'user' concurrently")
		}
		if b.Role == "" {
			return fmt.Errorf("binding role cannot be empty")
		}
		if _, exists := config.Roles[b.Role]; !exists {
			return fmt.Errorf("binding role %q does not exist in defined roles", b.Role)
		}
	}

	for role, rolePolicy := range config.Roles {
		for _, target := range rolePolicy.Network.AllowedTargets {
			if target == "*" {
				return fmt.Errorf("wildcard target '*' is not allowed in role %q", role)
			}
		}
		for _, tool := range rolePolicy.MCP.AllowedTools {
			if tool == "*" {
				return fmt.Errorf("wildcard tool '*' is not allowed in role %q", role)
			}
		}
	}
	return nil
}
