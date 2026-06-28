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

package main

import (
	"fmt"
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

	oidcRoles := toStringSlice(claims["roles"])
	oidcGroups := toStringSlice(claims["groups"])
	oidcSub, _ := claims["sub"].(string)

	// Resolve roles based on configured bindings and explicit OIDC roles
	resolvedRoles := make(map[string]bool)
	if h.Policy != nil {
		// 1. Map OIDC groups and users to roles via configured bindings (RBAC mapping)
		for _, b := range h.Policy.Bindings {
			if b.Group != "" {
				for _, cg := range oidcGroups {
					if b.Group == cg {
						resolvedRoles[b.Role] = true
					}
				}
			}
			if b.User != "" && oidcSub != "" {
				if b.User == oidcSub {
					resolvedRoles[b.Role] = true
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

	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactExpiration,
		IDs:  []biscuit.Term{biscuit.Date(token.Expiry)},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add expiration fact: %w", err)
	}

	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactNode,
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add node fact: %w", err)
	}

	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactClientPeerID,
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add client_peer_id fact: %w", err)
	}

	// Dynamic claims to facts mapping using api.OIDCClaimToFact
	if err := translateClaimsToFacts(builder, claims); err != nil {
		return nil, err
	}

	// Assert resolved authorized roles in the token
	for role := range resolvedRoles {
		if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactRole,
			IDs:  []biscuit.Term{biscuit.String(role)},
		}}); err != nil {
			return nil, fmt.Errorf("failed to add role fact: %w", err)
		}

		if h.Policy != nil {
			if rolePolicy, ok := h.Policy.Roles[role]; ok {
				for _, tool := range rolePolicy.MCP.AllowedServers {
					if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
						Name: api.FactMCPServer,
						IDs:  []biscuit.Term{biscuit.String(tool)},
					}}); err != nil {
						logger.Errorw("Failed to add MCP tool fact to biscuit", "peer_id", remotePeer, "tool", tool, "error", err)
					}
				}
				for _, target := range rolePolicy.Network.AllowedTargets {
					if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
						Name: api.FactNetworkTarget,
						IDs:  []biscuit.Term{biscuit.String(target)},
					}}); err != nil {
						logger.Errorw("Failed to add network target fact to biscuit", "peer_id", remotePeer, "target", target, "error", err)
					}
				}
				for _, customFact := range rolePolicy.CustomDatalog {
					trimmed := strings.TrimRight(strings.TrimSpace(customFact), ";")
					if trimmed == "" {
						continue
					}
					func() {
						defer func() {
							if r := recover(); r != nil {
								logger.Errorw("Panic parsing custom fact", "peer_id", remotePeer, "fact", trimmed, "recover", r)
							}
						}()
						fact, err := parser.FromStringFact(trimmed)
						if err != nil {
							logger.Errorw("Failed to parse custom fact", "peer_id", remotePeer, "fact", trimmed, "error", err)
							return
						}
						if err := builder.AddAuthorityFact(fact); err != nil {
							logger.Errorw("Failed to add custom fact to biscuit", "peer_id", remotePeer, "fact", trimmed, "error", err)
						}
					}()
				}
			}
		}
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

	timeCheck, err := parser.FromStringCheck(`check if time($time), expiration($exp), $time <= $exp`)
	if err != nil {
		return nil, fmt.Errorf("failed to parse time check: %w", err)
	}

	rule, err := parser.FromStringPolicy("allow if true")
	if err != nil {
		return nil, fmt.Errorf("failed to parse allow policy: %w", err)
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
				Name: "time",
				IDs:  []biscuit.Term{biscuit.Date(time.Now())},
			},
		})

		authorizer.AddCheck(timeCheck)
		authorizer.AddPolicy(rule)

		if err := authorizer.Authorize(); err == nil {
			return b, nil
		} else {
			lastErr = err
		}
	}

	return nil, fmt.Errorf("no valid key found for verification: %v", lastErr)
}

func translateClaimsToFacts(builder biscuit.Builder, claims map[string]any) error {
	for claimKey, factName := range api.OIDCClaimToFact {
		val, ok := claims[claimKey]
		if !ok || val == nil {
			continue
		}
		switch factName {
		case api.FactUser, api.FactEmail:
			if strVal, ok := val.(string); ok && strVal != "" {
				if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
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
				if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
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
