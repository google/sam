package node

import (
	"strings"
	"testing"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
)

func ruleToString(r biscuit.Rule) string {
	head := r.Head.String()
	if len(r.Body) == 0 {
		return head
	}
	var bodyParts []string
	for _, b := range r.Body {
		bodyParts = append(bodyParts, b.String())
	}
	return head + " <- " + strings.Join(bodyParts, ", ")
}

func TestBuildPolicyRules(t *testing.T) {
	roles := []*api.PolicyRole{
		{
			Name:            "test-role",
			AllowedTargets:  []string{"*", "node:peer-abc", "custom-fact:custom-val", "legacy-peer"},
			AllowedServices: []string{"*:*", "mcp:*", "mcp:*.suffix", "mcp:prefix.*", "mcp:exact"},
			CustomDatalog: []string{
				"custom_rule($x) <- fact($x);",
				"custom_fact(\"hello\")",
			},
		},
	}
	bindings := []*api.PolicyBinding{
		{
			Role:    "test-role",
			Members: []string{"sam:system:authenticated", "user:alice"},
		},
	}

	rules := BuildPolicyRules(roles, bindings)

	expectedStrings := map[string]bool{
		"role(\"test-role\")":                                                          false,
		"role(\"test-role\") <- user(\"alice\")":                                       false,
		"granted_service_all_types() <- role(\"test-role\")":                           false,
		"granted_service_all(\"mcp\") <- role(\"test-role\")":                          false,
		"granted_service_suffix(\"mcp\", \".suffix\") <- role(\"test-role\")":          false,
		"granted_service_prefix(\"mcp\", \"prefix.\") <- role(\"test-role\")":          false,
		"granted_service_exact(\"mcp\", \"exact\") <- role(\"test-role\")":             false,
		"target_unrestricted() <- role(\"test-role\")":                                 false,
		"target_restricted() <- role(\"test-role\")":                                   false,
		"granted_target_exact(\"node\", \"peer-abc\") <- role(\"test-role\")":          false,
		"granted_target_exact(\"custom-fact\", \"custom-val\") <- role(\"test-role\")": false,
		"granted_target_exact(\"node\", \"legacy-peer\") <- role(\"test-role\")":       false,
		"custom_rule($x) <- fact($x)":                                                  false,
		"custom_fact(\"hello\")":                                                       false,
	}

	for _, rule := range rules {
		rStr := ruleToString(rule)
		found := false
		for k := range expectedStrings {
			if rStr == k {
				expectedStrings[k] = true
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Unexpected rule generated: %q", rStr)
		}
	}

	for k, v := range expectedStrings {
		if !v {
			t.Errorf("Expected rule was not generated: %q", k)
		}
	}
}
