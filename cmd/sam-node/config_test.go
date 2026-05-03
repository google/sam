package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadNodeConfig(t *testing.T) {
	// 1. Test valid YAML with policies and services
	validYAML := `
version: "v1alpha1"
attenuation:
  policies:
    - 'deny if user("untrusted_sub_id");'
  checks:
    - 'check if time($time), $time < 2026-12-31T00:00:00Z;'
services:
  - type: "mcp"
    name: "test-mcp"
    description: "Test MCP Service"
    target_url: "http://localhost:8080"
  - type: "inference"
    name: "test-inference"
    description: "Test Inference Service"
    command: ["python3", "-m", "llama"]
    env:
      MODEL_PATH: "/models/llama"
`
	dir := t.TempDir()
	validFile := filepath.Join(dir, "sam-node.yaml")
	if err := os.WriteFile(validFile, []byte(validYAML), 0644); err != nil {
		t.Fatal(err)
	}

	config, err := LoadNodeConfig(validFile)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(config.Policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(config.Policies))
	}
	if len(config.Checks) != 1 {
		t.Errorf("expected 1 check, got %d", len(config.Checks))
	}
	if len(config.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(config.Services))
	}

	// Verify service 1
	s1 := config.Services[0]
	if s1.Type != "mcp" || s1.Name != "test-mcp" || s1.TargetURL != "http://localhost:8080" {
		t.Errorf("unexpected service 1: %+v", s1)
	}

	// Verify service 2
	s2 := config.Services[1]
	if s2.Type != "inference" || s2.Name != "test-inference" || len(s2.Command) != 3 || s2.Env["MODEL_PATH"] != "/models/llama" {
		t.Errorf("unexpected service 2: %+v", s2)
	}

	// 2. Test missing file
	missingFile := filepath.Join(dir, "nonexistent.yaml")
	config, err = LoadNodeConfig(missingFile)
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if config == nil {
		t.Fatal("expected non-nil config for missing file")
	}
	if len(config.Policies) != 0 {
		t.Errorf("expected empty policies, got %d", len(config.Policies))
	}
}
