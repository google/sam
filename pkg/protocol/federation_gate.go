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

package protocol

import (
	"context"
	"fmt"
	"strings"

	"sam/pkg/identity"
)

type passportClaimsContextKey struct{}

func withAuthenticatedPassportClaims(ctx context.Context, claims *identity.PassportClaims) context.Context {
	return context.WithValue(ctx, passportClaimsContextKey{}, claims)
}

func authenticatedPassportClaimsFromContext(ctx context.Context) (*identity.PassportClaims, bool) {
	claims, ok := ctx.Value(passportClaimsContextKey{}).(*identity.PassportClaims)
	if !ok || claims == nil {
		return nil, false
	}
	return claims, true
}

// PassportGate is a FederationGate that allows a peer only when it presents a
// valid passport biscuit bound to the peer and federation.
type PassportGate struct {
	federationID string
}

// NewPassportGate creates a gate scoped to the default federation.
func NewPassportGate() *PassportGate {
	return &PassportGate{federationID: "default"}
}

// NewPassportGateWithCleanup returns a passport gate and a no-op close function
// for compatibility with setup call-sites expecting a cleanup callback.
func NewPassportGateWithCleanup() (*PassportGate, func() error, error) {
	return NewPassportGate(), func() error { return nil }, nil
}

// Allow returns nil when the requester has authenticated passport claims.
func (g *PassportGate) Allow(ctx context.Context, peerID string, _ string) error {
	if peerID == "" {
		return fmt.Errorf("empty peer ID")
	}
	claims, ok := authenticatedPassportClaimsFromContext(ctx)
	if !ok {
		return fmt.Errorf("authentication error: missing authenticated passport claims")
	}
	if strings.TrimSpace(claims.PeerID) != strings.TrimSpace(peerID) {
		return fmt.Errorf("authentication error: authenticated peer mismatch")
	}
	if strings.TrimSpace(g.federationID) != "" && strings.TrimSpace(claims.FederationID) != strings.TrimSpace(g.federationID) {
		return fmt.Errorf("authentication error: passport federation mismatch")
	}
	return nil
}
