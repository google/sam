package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicyConfig(t *testing.T) {
	// 1. Test valid YAML
	validYAML := `
version: "v1alpha1"
roles:
  data-scientist:
    network:
      allowed_targets: ["db-agent.data-mesh"]
    mcp:
      allowed_tools: ["query_database"]
    custom_datalog:
      - 'department("analytics");'
`
	dir := t.TempDir()
	validFile := filepath.Join(dir, "valid.yaml")
	if err := os.WriteFile(validFile, []byte(validYAML), 0644); err != nil {
		t.Fatal(err)
	}

	config, err := LoadPolicyConfig(validFile)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if config.Version != "v1alpha1" {
		t.Errorf("expected version v1alpha1, got %s", config.Version)
	}
	role, ok := config.Roles["data-scientist"]
	if !ok {
		t.Fatal("expected role data-scientist to exist")
	}
	if len(role.Network.AllowedTargets) != 1 || role.Network.AllowedTargets[0] != "db-agent.data-mesh" {
		t.Errorf("unexpected allowed targets: %v", role.Network.AllowedTargets)
	}
	if len(role.MCP.AllowedTools) != 1 || role.MCP.AllowedTools[0] != "query_database" {
		t.Errorf("unexpected allowed tools: %v", role.MCP.AllowedTools)
	}
	if len(role.CustomDatalog) != 1 || role.CustomDatalog[0] != `department("analytics");` {
		t.Errorf("unexpected custom datalog: %v", role.CustomDatalog)
	}

	// 2. Test invalid YAML
	invalidYAML := `
version: "v1alpha1"
roles:
  data-scientist:
    network:
      allowed_targets: [missing closing bracket
`
	invalidFile := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(invalidFile, []byte(invalidYAML), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = LoadPolicyConfig(invalidFile)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}

	// 3. Test missing file
	missingFile := filepath.Join(dir, "nonexistent.yaml")
	config, err = LoadPolicyConfig(missingFile)
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if config == nil {
		t.Fatal("expected non-nil config for missing file")
	}
	if len(config.Roles) != 0 {
		t.Errorf("expected empty roles, got %d", len(config.Roles))
	}

	// 4. Test invalid custom datalog
	invalidDatalogYAML := `
version: "v1alpha1"
roles:
  data-scientist:
    custom_datalog:
      - 'invalid fact syntax'
`
	invalidDatalogFile := filepath.Join(dir, "invalid_datalog.yaml")
	if err := os.WriteFile(invalidDatalogFile, []byte(invalidDatalogYAML), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = LoadPolicyConfig(invalidDatalogFile)
	if err == nil {
		t.Error("expected error for invalid custom datalog, got nil")
	}

	// 5. Test wildcard rejection
	wildcardYAML := `
version: "v1alpha1"
roles:
  admin:
    network:
      allowed_targets: ["*"]
`
	wildcardFile := filepath.Join(dir, "wildcard.yaml")
	if err := os.WriteFile(wildcardFile, []byte(wildcardYAML), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = LoadPolicyConfig(wildcardFile)
	if err == nil {
		t.Error("expected error for wildcard target, got nil")
	}
}
