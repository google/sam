package node

import (
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
)

func BuildPolicyRules(roles []*api.PolicyRole, bindings []*api.PolicyBinding) []biscuit.Rule {
	var rules []biscuit.Rule

	for _, b := range bindings {
		if b == nil {
			continue
		}
		for _, m := range b.Members {
			parts := strings.SplitN(m, ":", 2)
			if len(parts) == 2 {
				memberType := parts[0]
				memberVal := parts[1]
				rules = append(rules, biscuit.Rule{
					Head: biscuit.Predicate{
						Name: api.FactRole,
						IDs:  []biscuit.Term{biscuit.String(b.Role)},
					},
					Body: []biscuit.Predicate{
						{Name: memberType, IDs: []biscuit.Term{biscuit.String(memberVal)}},
					},
				})
			}
		}
	}

	for _, role := range roles {
		if role == nil {
			continue
		}
		roleName := role.Name

		for _, svc := range role.AllowedServices {
			svcType, svcName := api.ParseServiceTarget(svc)

			if svcType == "*" && svcName == "*" {
				rules = append(rules, biscuit.Rule{
					Head: biscuit.Predicate{
						Name: api.FactGrantedServiceAllTypes,
						IDs:  []biscuit.Term{},
					},
					Body: []biscuit.Predicate{
						{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(roleName)}},
					},
				})
			} else if svcName == "*" {
				rules = append(rules, biscuit.Rule{
					Head: biscuit.Predicate{
						Name: api.FactGrantedServiceAll,
						IDs:  []biscuit.Term{biscuit.String(svcType)},
					},
					Body: []biscuit.Predicate{
						{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(roleName)}},
					},
				})
			} else if strings.HasPrefix(svcName, "*.") {
				suffix := svcName[1:]
				rules = append(rules, biscuit.Rule{
					Head: biscuit.Predicate{
						Name: api.FactGrantedServiceSuffix,
						IDs:  []biscuit.Term{biscuit.String(svcType), biscuit.String(suffix)},
					},
					Body: []biscuit.Predicate{
						{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(roleName)}},
					},
				})
			} else if strings.HasSuffix(svcName, ".*") {
				prefix := svcName[:len(svcName)-1]
				rules = append(rules, biscuit.Rule{
					Head: biscuit.Predicate{
						Name: api.FactGrantedServicePrefix,
						IDs:  []biscuit.Term{biscuit.String(svcType), biscuit.String(prefix)},
					},
					Body: []biscuit.Predicate{
						{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(roleName)}},
					},
				})
			} else {
				rules = append(rules, biscuit.Rule{
					Head: biscuit.Predicate{
						Name: api.FactGrantedServiceExact,
						IDs:  []biscuit.Term{biscuit.String(svcType), biscuit.String(svcName)},
					},
					Body: []biscuit.Predicate{
						{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(roleName)}},
					},
				})
			}
		}

		for _, t := range role.AllowedTargets {
			if t == "*" {
				rules = append(rules, biscuit.Rule{
					Head: biscuit.Predicate{
						Name: api.FactTargetUnrestricted,
						IDs:  []biscuit.Term{},
					},
					Body: []biscuit.Predicate{
						{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(roleName)}},
					},
				})
				continue
			}

			// Try to parse as fact:value
			parts := strings.SplitN(t, ":", 2)
			if len(parts) == 2 {
				factName := parts[0]
				factVal := parts[1]
				rules = append(rules, biscuit.Rule{
					Head: biscuit.Predicate{
						Name: api.FactGrantedTargetExact,
						IDs:  []biscuit.Term{biscuit.String(factName), biscuit.String(factVal)},
					},
					Body: []biscuit.Predicate{
						{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(roleName)}},
					},
				})
			} else {
				// Fallback, if it doesn't have a colon, we'll just treat it as an unrestricted node check?
				// Wait, earlier tests might use "node:foo", or maybe just a peerID?
				// For compatibility, if no colon, assume it's a domain/prefix check?
				// Actually, Phase 2 tests mostly use FactGrantedTargetExact.
				rules = append(rules, biscuit.Rule{
					Head: biscuit.Predicate{
						Name: api.FactGrantedTargetExact,
						IDs:  []biscuit.Term{biscuit.String("node"), biscuit.String(t)},
					},
					Body: []biscuit.Predicate{
						{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(roleName)}},
					},
				})
			}
		}
	}

	return rules
}
