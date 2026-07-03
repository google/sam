// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hub

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/peer"
)

func (h *Hub) mintBiscuitToken(claims jwt.MapClaims, token *oidc.IDToken, remotePeer peer.ID) ([]byte, error) {
	if token == nil {
		return nil, fmt.Errorf("token cannot be nil")
	}
	if claims == nil {
		return nil, fmt.Errorf("claims cannot be nil")
	}

	oidcRoles := toStringSlice(claims["roles"])
	oidcGroups := toStringSlice(claims["groups"])
	oidcSub, _ := claims["sub"].(string)
	oidcEmail, _ := claims["email"].(string)

	// Resolve roles based on configured bindings and explicit OIDC roles
	resolvedRoles := make(map[string]bool)
	if h.Policy != nil {
		// 1. Evaluate explicit Policy Bindings
		for _, b := range h.Policy.Bindings {
			for _, member := range b.Members {
				if member == api.SystemAuthenticated {
					resolvedRoles[b.Role] = true
					break
				}

				parts := strings.SplitN(member, ":", 2)
				if len(parts) != 2 {
					continue // validated at startup, but ignore if broken
				}
				prefix := parts[0]
				value := parts[1]

				switch prefix {
				case api.FactGroup:
					for _, cg := range oidcGroups {
						if value == cg {
							resolvedRoles[b.Role] = true
						}
					}
				case api.FactUser:
					if oidcSub != "" && value == oidcSub {
						resolvedRoles[b.Role] = true
					}
				case api.FactEmail:
					if oidcEmail != "" && value == oidcEmail {
						resolvedRoles[b.Role] = true
					}
				case api.FactNode:
					if value == remotePeer.String() {
						resolvedRoles[b.Role] = true
					}
				}
			}
		}

		// 2. Validate and accept pre-resolved OIDC roles directly if defined in policy (Zero-Trust check)
		for _, r := range oidcRoles {
			if _, exists := h.Policy.Roles[r]; exists {
				resolvedRoles[r] = true
			}
		}
	}

	builder := biscuit.NewBuilder(h.KeyRing.GetCurrentKey())

	addedFacts := make(map[string]bool)
	addFact := func(fact biscuit.Fact) error {
		factStr := fact.String()
		if addedFacts[factStr] {
			return nil
		}
		if err := builder.AddAuthorityFact(fact); err != nil {
			return err
		}
		addedFacts[factStr] = true
		return nil
	}

	if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactExpiration,
		IDs:  []biscuit.Term{biscuit.Date(token.Expiry)},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add expiration fact: %w", err)
	}

	if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactNode,
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add node fact: %w", err)
	}

	if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactClientPeerID,
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add client_peer_id fact: %w", err)
	}

	// Dynamic claims to facts mapping using api.OIDCClaimToFact
	if err := translateClaimsToFacts(addFact, claims); err != nil {
		return nil, err
	}

	// Assert resolved authorized roles in the token
	roles := make([]string, 0, len(resolvedRoles))
	for role := range resolvedRoles {
		roles = append(roles, role)
	}
	sort.Strings(roles)

	var errs []error
	for _, role := range roles {
		if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactRole,
			IDs:  []biscuit.Term{biscuit.String(role)},
		}}); err != nil {
			errs = append(errs, fmt.Errorf("failed to add role fact for %s: %w", role, err))
			continue
		}

		if h.Policy != nil {
			if rolePolicy, ok := h.Policy.Roles[role]; ok {
				for _, svc := range rolePolicy.AllowedServices {
					svcType, svcName := api.ParseServiceTarget(svc)

					if svcType == "*" && svcName == "*" {
						if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
							Name: api.FactGrantedServiceAllTypes,
							IDs:  []biscuit.Term{},
						}}); err != nil {
							errs = append(errs, fmt.Errorf("failed to add granted_service_all_types fact: %w", err))
						}
					} else if svcName == "*" {
						if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
							Name: api.FactGrantedServiceAll,
							IDs:  []biscuit.Term{biscuit.String(svcType)},
						}}); err != nil {
							errs = append(errs, fmt.Errorf("failed to add granted_service_all fact: %w", err))
						}
					} else if strings.HasPrefix(svcName, "*.") {
						suffix := svcName[1:]
						if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
							Name: api.FactGrantedServiceSuffix,
							IDs:  []biscuit.Term{biscuit.String(svcType), biscuit.String(suffix)},
						}}); err != nil {
							errs = append(errs, fmt.Errorf("failed to add granted_service_suffix fact: %w", err))
						}
					} else if strings.HasSuffix(svcName, ".*") {
						prefix := svcName[:len(svcName)-1]
						if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
							Name: api.FactGrantedServicePrefix,
							IDs:  []biscuit.Term{biscuit.String(svcType), biscuit.String(prefix)},
						}}); err != nil {
							errs = append(errs, fmt.Errorf("failed to add granted_service_prefix fact: %w", err))
						}
					} else {
						if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
							Name: api.FactGrantedServiceExact,
							IDs:  []biscuit.Term{biscuit.String(svcType), biscuit.String(svcName)},
						}}); err != nil {
							errs = append(errs, fmt.Errorf("failed to add granted_service_exact fact: %w", err))
						}
					}
				}
				for _, target := range rolePolicy.AllowedTargets {
					targetFact, targetVal := api.ParseServiceTarget(target)

					if targetFact == "*" && targetVal == "*" {
						if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
							Name: api.FactGrantedTargetAllFacts,
							IDs:  []biscuit.Term{},
						}}); err != nil {
							errs = append(errs, fmt.Errorf("failed to add granted_target_all_facts fact: %w", err))
						}
					} else if targetVal == "*" {
						if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
							Name: api.FactGrantedTargetAll,
							IDs:  []biscuit.Term{biscuit.String(targetFact)},
						}}); err != nil {
							errs = append(errs, fmt.Errorf("failed to add granted_target_all fact: %w", err))
						}
					} else if strings.HasPrefix(targetVal, "*.") {
						suffix := targetVal[1:]
						if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
							Name: api.FactGrantedTargetSuffix,
							IDs:  []biscuit.Term{biscuit.String(targetFact), biscuit.String(suffix)},
						}}); err != nil {
							errs = append(errs, fmt.Errorf("failed to add granted_target_suffix fact: %w", err))
						}
					} else if strings.HasSuffix(targetVal, ".*") {
						prefix := targetVal[:len(targetVal)-1]
						if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
							Name: api.FactGrantedTargetPrefix,
							IDs:  []biscuit.Term{biscuit.String(targetFact), biscuit.String(prefix)},
						}}); err != nil {
							errs = append(errs, fmt.Errorf("failed to add granted_target_prefix fact: %w", err))
						}
					} else {
						if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
							Name: api.FactGrantedTargetExact,
							IDs:  []biscuit.Term{biscuit.String(targetFact), biscuit.String(targetVal)},
						}}); err != nil {
							errs = append(errs, fmt.Errorf("failed to add granted_target_exact fact: %w", err))
						}
					}
				}
				for _, customFact := range rolePolicy.CustomDatalog {
					trimmed := strings.TrimRight(strings.TrimSpace(customFact), ";")
					if trimmed == "" {
						continue
					}
					var factErr error
					func() {
						defer func() {
							if r := recover(); r != nil {
								factErr = fmt.Errorf("panic parsing custom fact %q: %v", trimmed, r)
							}
						}()
						fact, err := parser.FromStringFact(trimmed)
						if err != nil {
							factErr = fmt.Errorf("failed to parse custom fact %q: %w", trimmed, err)
							return
						}
						if err := addFact(fact); err != nil {
							factErr = fmt.Errorf("failed to add custom fact %q: %w", trimmed, err)
						}
					}()
					if factErr != nil {
						errs = append(errs, factErr)
					}
				}
			}
		}
	}

	hasTargets := false
	for _, role := range roles {
		if h.Policy != nil {
			if rolePolicy, ok := h.Policy.Roles[role]; ok {
				if len(rolePolicy.AllowedTargets) > 0 {
					hasTargets = true
					break
				}
			}
		}
	}
	if hasTargets {
		if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: api.FactTargetRestricted}}); err != nil {
			errs = append(errs, err)
		}
	} else {
		if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: api.FactTargetUnrestricted}}); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("biscuit policy validation failed: %w", errors.Join(errs...))
	}

	t, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build biscuit: %w", err)
	}

	biscuitData, err := t.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize biscuit: %w", err)
	}

	return biscuitData, nil
}

func (h *Hub) verifyBiscuit(biscuitData []byte, remotePeer peer.ID) (*biscuit.Biscuit, error) {
	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		return nil, fmt.Errorf("malformed biscuit: %w", err)
	}

	var authOpts []biscuit.AuthorizerOption
	if h.BiscuitTimeout > 0 {
		authOpts = append(authOpts, biscuit.WithWorldOptions(datalog.WithMaxDuration(h.BiscuitTimeout)))
	}

	keys := h.KeyRing.GetAllValidPublicKeys()
	var lastErr error
	for _, pubKey := range keys {
		authorizer, err := b.Authorizer(pubKey, authOpts...)
		if err != nil {
			lastErr = err
			continue
		}

		authorizer.AddFact(biscuit.Fact{
			Predicate: biscuit.Predicate{
				Name: api.FactTime,
				IDs:  []biscuit.Term{biscuit.Date(time.Now())},
			},
		})

		authorizer.AddCheck(api.HubStaticTimeCheck)
		authorizer.AddPolicy(api.AllowIfTruePolicy)

		if err := authorizer.Authorize(); err == nil {
			return b, nil
		} else {
			lastErr = err
		}
	}

	return nil, fmt.Errorf("no valid key found for verification: %v", lastErr)
}

func translateClaimsToFacts(addFact func(biscuit.Fact) error, claims map[string]any) error {
	claimMap := api.OIDCClaimToFact()
	keys := make([]string, 0, len(claimMap))
	for k := range claimMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, claimKey := range keys {
		factName := claimMap[claimKey]
		val, ok := claims[claimKey]
		if !ok || val == nil {
			continue
		}
		switch factName {
		case api.FactUser, api.FactEmail:
			if strVal, ok := val.(string); ok && strVal != "" {
				if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: factName,
					IDs:  []biscuit.Term{biscuit.String(strVal)},
				}}); err != nil {
					return fmt.Errorf("failed to add %s fact: %w", factName, err)
				}
			}
		case api.FactGroup:
			groups := toStringSlice(val)
			seen := make(map[string]bool)
			for _, g := range groups {
				if seen[g] {
					continue
				}
				seen[g] = true
				if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: factName,
					IDs:  []biscuit.Term{biscuit.String(g)},
				}}); err != nil {
					return fmt.Errorf("failed to add %s fact: %w", factName, err)
				}
			}
		}
	}
	return nil
}

func toStringSlice(val any) []string {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case []string:
		return v
	case []any:
		var res []string
		for _, item := range v {
			if str, ok := item.(string); ok && str != "" {
				res = append(res, str)
			}
		}
		return res
	}
	return nil
}
