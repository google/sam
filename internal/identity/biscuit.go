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

package identity

import (
	"crypto/ed25519"
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

// // MintBiscuitToken generates a signed Biscuit token for a peer with policy rules based on JWT claims.
func MintBiscuitToken(signingKey ed25519.PrivateKey, claims jwt.MapClaims, token *oidc.IDToken, remotePeer peer.ID, policy *api.PolicyConfig) ([]byte, error) {
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

	resolvedRoles := make(map[string]bool)
	if policy != nil {
		for _, b := range policy.Bindings {
			for _, member := range b.Members {
				if member == api.SystemAuthenticated {
					resolvedRoles[b.Role] = true
					break
				}

				parts := strings.SplitN(member, ":", 2)
				if len(parts) != 2 {
					continue
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

		for _, r := range oidcRoles {
			if _, exists := policy.Roles[r]; exists {
				resolvedRoles[r] = true
			}
		}
	}

	roles := make([]string, 0, len(resolvedRoles))
	for role := range resolvedRoles {
		roles = append(roles, role)
	}

	// Ensure all tokens have a defined sam:role. If no custom role is resolved,
	// assign the default node role: sam:role:node.
	hasSamRole := false
	for _, r := range roles {
		if strings.HasPrefix(r, "sam:role:") {
			hasSamRole = true
			break
		}
	}
	if !hasSamRole {
		roles = append(roles, api.RoleNode)
	}

	return mintBiscuit(signingKey, remotePeer, roles, token.Expiry, policy, claims)
}

func mintBiscuit(signingKey ed25519.PrivateKey, remotePeer peer.ID, roles []string, expiration time.Time, policy *api.PolicyConfig, claims jwt.MapClaims) ([]byte, error) {
	builder := biscuit.NewBuilder(signingKey)
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
		IDs:  []biscuit.Term{biscuit.Date(expiration)},
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

	if claims != nil {
		if err := translateClaimsToFacts(addFact, claims); err != nil {
			return nil, err
		}
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

		if role == api.RoleRouter {
			if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactRight,
				IDs:  []biscuit.Term{biscuit.String(api.RightRelay)},
			}}); err != nil {
				errs = append(errs, fmt.Errorf("failed to add relay right: %w", err))
			}
			if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactTargetUnrestricted,
				IDs:  []biscuit.Term{},
			}}); err != nil {
				errs = append(errs, fmt.Errorf("failed to add target unrestricted: %w", err))
			}
			continue
		}

		if policy != nil {
			if rolePolicy, ok := policy.Roles[role]; ok {
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
		if policy != nil {
			if rolePolicy, ok := policy.Roles[role]; ok {
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

	bBytes, err := t.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize biscuit: %w", err)
	}

	return bBytes, nil
}

// VerifyBiscuit verifies the validity of a Biscuit token.
// It ensures that:
// 1. The token is cryptographically signed by one of the trustedPublicKeys.
// 2. The token is not expired.
// 3. The token is securely bound to the expected remotePeer.
func VerifyBiscuit(biscuitData []byte, expectedPeer peer.ID, trustedPublicKeys []ed25519.PublicKey, timeout time.Duration) (*biscuit.Biscuit, error) {
	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		return nil, fmt.Errorf("malformed biscuit: %w", err)
	}

	var authOpts []biscuit.AuthorizerOption
	if timeout > 0 {
		authOpts = append(authOpts, biscuit.WithWorldOptions(datalog.WithMaxDuration(timeout)))
	}

	var lastErr error
	var authorized bool
	for _, pubKey := range trustedPublicKeys {
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
			authorized = true
			break
		} else {
			lastErr = err
		}
	}

	if !authorized {
		return nil, fmt.Errorf("no valid key found for verification: %v", lastErr)
	}

	// Enforce hardware binding
	boundFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(expectedPeer.String())},
	}}
	if _, err := b.GetBlockID(boundFact); err != nil {
		return nil, fmt.Errorf("token is not bound to peer %s: %w", expectedPeer, err)
	}

	return b, nil
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

// MintBootstrapBiscuitToken generates a signed Biscuit token for a peer using a bootstrap role.
func MintBootstrapBiscuitToken(signingKey ed25519.PrivateKey, remotePeer peer.ID, role string, expiration time.Time, policy *api.PolicyConfig) ([]byte, error) {
	return mintBiscuit(signingKey, remotePeer, []string{role}, expiration, policy, nil)
}
