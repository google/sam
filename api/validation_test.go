package api

import (
	"testing"
)

func TestValidateServiceFormat(t *testing.T) {
	tests := []struct {
		name    string
		svc     string
		wantErr bool
	}{
		{"valid exact", "mcp://my-service.local", false},
		{"valid prefix wildcard", "mcp://*.service.local", false},
		{"valid suffix wildcard", "mcp://service.*", false},
		{"valid just wildcard", "mcp://*", false},
		{"valid subdomains", "mcp://a.b.c.d", false},
		{"invalid no type", "://my-service", true},
		{"invalid fallback", "mcp-service", true},
		{"invalid consecutive dots", "mcp://my..service", true},
		{"invalid wildcard middle", "mcp://my.*.service", true},
		{"valid with underscore", "mcp://service_name", false},
		{"invalid suffix wildcard without dot", "mcp://service.inc*", true},
		{"valid exact with path", "mcp://my-service/local", false},
		{"invalid legacy mcp: format", "mcp:my-service.local", true},
		{"invalid with query", "mcp://my-service?query=1", true},
		{"invalid with fragment", "mcp://my-service#fragment", true},
		{"invalid with query and fragment", "mcp://my-service?query=1#fragment", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServiceFormat(tt.svc)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateServiceFormat() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTargetFormat(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"valid target", "group:backend", false},
		{"valid email", "email:foo@bar.com", false},
		{"valid wildcard", "*", false},
		{"invalid no colon", "group-backend", true},
		{"invalid empty fact", ":backend", true},
		{"invalid empty value", "group:", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTargetFormat(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTargetFormat() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
