package node

import (
	"fmt"
	"os"
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/google/sam/api"
	"gopkg.in/yaml.v2"
)

type NodeConfigComplete struct {
	Policies []biscuit.Policy
	Checks   []biscuit.Check
	Rules    []biscuit.Rule
	Services []api.ServiceConfig
}

// LoadNodeConfig loads the node configuration from the specified path.
// If the file is missing, it returns an empty initialized config.
func LoadNodeConfig(path string) (*NodeConfigComplete, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &NodeConfigComplete{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config api.NodeConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	complete := &NodeConfigComplete{
		Services: config.Services,
	}

	for i, svc := range config.Services {
		if err := api.ValidateServiceFormat(svc.Type + "://" + svc.Name); err != nil {
			return nil, fmt.Errorf("invalid service config at index %d: %w", i, err)
		}
	}

	for _, pStr := range config.Attenuation.Policies {
		trimmed := strings.TrimRight(strings.TrimSpace(pStr), ";")
		p, err := parser.FromStringPolicy(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid local policy syntax %q: %w", pStr, err)
		}
		complete.Policies = append(complete.Policies, p)
	}

	for _, cStr := range config.Attenuation.Checks {
		trimmed := strings.TrimRight(strings.TrimSpace(cStr), ";")
		c, err := parser.FromStringCheck(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid local check syntax %q: %w", cStr, err)
		}
		complete.Checks = append(complete.Checks, c)
	}

	for _, rStr := range config.Attenuation.Rules {
		trimmed := strings.TrimRight(strings.TrimSpace(rStr), ";")
		r, err := parser.FromStringRule(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid local rule syntax %q: %w", rStr, err)
		}
		complete.Rules = append(complete.Rules, r)
	}

	return complete, nil
}
