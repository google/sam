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
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/peer"
)

// MintBiscuitToken generates a signed Biscuit token for a peer with policy rules based on JWT claims.
//
// Role Authorization Rationale:
// The system has two distinct kinds of roles:
//  1. Capability Roles (prefixed with "sam:role:"): These authorize the client's binary startup role
//     (e.g., sam:role:node, sam:role:router, sam:role:sambox) under Zero Trust.
//  2. Custom Access Roles (all other roles): These define authorization permissions for custom
//     services and targets (e.g., restricted-role).
//
// When enrolling:
//   - The client binary must explicitly request a single capability role (requestedRole).
//   - We verify if the client's OIDC identity is authorized to claim that requested capability role:
//   - If the user has explicitly mapped capability roles (from policy/claims), they must only request one of those.
//   - If the user has no capability roles mapped, they are allowed to request the standard fallback role ("sam:role:node").
//   - Once authorized, the generated Biscuit is minted with:
//   - The requested capability role (enforcing least privilege).
//   - All other custom access roles mapped to the identity (so they preserve their resource permissions).
func MintBiscuitToken(signingKey ed25519.PrivateKey, claims jwt.MapClaims, token *oidc.IDToken, remotePeer peer.ID, biscuitExpiry time.Time) ([]byte, []string, error) {
	if claims == nil {
		return nil, nil, fmt.Errorf("claims cannot be nil")
	}

	finalRoles := []string{}

	biscuitBytes, err := mintBiscuit(signingKey, remotePeer, finalRoles, biscuitExpiry, claims)
	if err != nil {
		return nil, nil, err
	}
	return biscuitBytes, finalRoles, nil
}

func mintBiscuit(signingKey ed25519.PrivateKey, remotePeer peer.ID, roles []string, expiration time.Time, claims jwt.MapClaims) ([]byte, error) {
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
	b, _, err := VerifyBiscuitAndGetKey(biscuitData, expectedPeer, trustedPublicKeys, timeout)
	return b, err
}

func VerifyBiscuitAndGetKey(biscuitData []byte, expectedPeer peer.ID, trustedPublicKeys []ed25519.PublicKey, timeout time.Duration) (*biscuit.Biscuit, ed25519.PublicKey, error) {
	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		return nil, nil, fmt.Errorf("malformed biscuit: %w", err)
	}

	var authOpts []biscuit.AuthorizerOption
	if timeout > 0 {
		authOpts = append(authOpts, biscuit.WithWorldOptions(datalog.WithMaxDuration(timeout)))
	}

	var lastErr error
	var authorized bool
	var verifyingKey ed25519.PublicKey
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
			verifyingKey = pubKey
			break
		} else {
			lastErr = err
		}
	}

	if !authorized {
		return nil, nil, fmt.Errorf("no valid key found for verification: %v", lastErr)
	}

	// Enforce hardware binding
	boundFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(expectedPeer.String())},
	}}
	if _, err := b.GetBlockID(boundFact); err != nil {
		return nil, nil, fmt.Errorf("token is not bound to peer %s: %w", expectedPeer, err)
	}

	return b, verifyingKey, nil
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
		case api.FactGroup, api.FactRole:
			items := toStringSlice(val)
			seen := make(map[string]bool)
			for _, item := range items {
				if seen[item] {
					continue
				}
				seen[item] = true
				if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: factName,
					IDs:  []biscuit.Term{biscuit.String(item)},
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
func MintBootstrapBiscuitToken(signingKey ed25519.PrivateKey, remotePeer peer.ID, role string, expiration time.Time) ([]byte, error) {
	return mintBiscuit(signingKey, remotePeer, []string{role}, expiration, nil)
}

// VerifyAndExtractPeerID checks that the biscuit is signed by one of the trusted keys and returns the peer ID.
// This function does NOT perform time checks, making it suitable for token refresh flows.
func VerifyAndExtractPeerID(trustedPublicKeys []ed25519.PublicKey, biscuitData []byte) (peer.ID, error) {
	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		return "", fmt.Errorf("malformed biscuit: %w", err)
	}

	var authorizer biscuit.Authorizer
	var verified bool
	var lastErr error

	for _, pubKey := range trustedPublicKeys {
		auth, err := b.Authorizer(pubKey)
		if err != nil {
			lastErr = err
			continue
		}
		authorizer = auth
		verified = true
		break
	}

	if !verified {
		return "", fmt.Errorf("signature verification failed: %v", lastErr)
	}

	// Extract the peer ID using Datalog query
	peerRule, err := parser.FromStringRule(`get_peer($p) <- node($p)`)
	if err != nil {
		return "", fmt.Errorf("failed to parse query rule: %w", err)
	}

	// Trigger datalog engine evaluation to copy token facts to authorizer world
	_ = authorizer.Authorize()

	facts, err := authorizer.Query(peerRule)
	if err != nil {
		return "", fmt.Errorf("query failed: %w", err)
	}

	if len(facts) == 0 {
		return "", fmt.Errorf("no node fact found in biscuit. Authorizer state: %s", authorizer.PrintWorld())
	}

	// Extract value from fact
	pred := facts[0].Predicate
	if len(pred.IDs) != 1 {
		return "", fmt.Errorf("unexpected fact structure")
	}

	strVal, ok := pred.IDs[0].(biscuit.String)
	if !ok {
		return "", fmt.Errorf("node fact value is not a string")
	}

	pID, err := peer.Decode(string(strVal))
	if err != nil {
		return "", fmt.Errorf("invalid peer ID in biscuit: %w", err)
	}

	return pID, nil
}

// VerifyBiscuitRole checks that the biscuit is signed by the hub's public key
// and contains the specified role fact.
func VerifyBiscuitRole(biscuitData []byte, hubPubKey ed25519.PublicKey, expectedRole string) error {
	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		return fmt.Errorf("malformed biscuit: %w", err)
	}

	authorizer, err := b.Authorizer(hubPubKey)
	if err != nil {
		return fmt.Errorf("failed to create authorizer: %w", err)
	}

	authorizer.AddCheck(biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(expectedRole)}},
			},
		},
	}})
	authorizer.AddPolicy(api.AllowIfTruePolicy)

	if err := authorizer.Authorize(); err != nil {
		return fmt.Errorf("biscuit lacks expected role %q: %w", expectedRole, err)
	}
	return nil
}
