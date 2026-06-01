package api

// PolicyConfig is the root authorization configuration for the SAM Hub.
type PolicyConfig struct {
	Version  string                `yaml:"version"`
	Bindings []Binding             `yaml:"bindings"`
	Roles    map[string]RolePolicy `yaml:"roles"`
}

type Binding struct {
	Group string `yaml:"group,omitempty"`
	User  string `yaml:"user,omitempty"`
	Role  string `yaml:"role"`
}

type RolePolicy struct {
	Network       NetworkPolicy `yaml:"network"`
	MCP           MCPPolicy     `yaml:"mcp"`
	CustomDatalog []string      `yaml:"custom_datalog"`
}

type NetworkPolicy struct {
	AllowedTargets []string `yaml:"allowed_targets"`
}

type MCPPolicy struct {
	AllowedTools []string `yaml:"allowed_tools"`
}

type ServiceConfig struct {
	Type        string            `yaml:"type"` // e.g., "mcp", "inference"
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	TargetURL   string            `yaml:"target_url,omitempty"`
	Command     []string          `yaml:"command,omitempty"`
	Env         map[string]string `yaml:"env,omitempty"`
}

// NodeConfig defines the optional attenuation rules and static services for a specific SAM Node.
type NodeConfig struct {
	Version     string          `yaml:"version"`
	Attenuation Attenuation     `yaml:"attenuation"`
	Services    []ServiceConfig `yaml:"services"`
}

type Attenuation struct {
	Policies []string `yaml:"policies"`
	Checks   []string `yaml:"checks"`
	Rules    []string `yaml:"rules"`
}
