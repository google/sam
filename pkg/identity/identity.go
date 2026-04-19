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
	"context"
	"crypto/ed25519"
	"time"
)

// Provider identifies the upstream identity provider that authenticated the workload.
type Provider string

const (
	ProviderGoogle    Provider = "google"
	ProviderGitHub    Provider = "github"
	ProviderSovereign Provider = "sovereign"
)

// OIDCIdentity is the normalized result of a verified OIDC ID token.
//
// The package does not implement the browser redirect or token exchange flow.
// Instead, a hub or caller injects an already-verified OIDC identity and SAM
// converts it into a signed voucher bound to a specific PeerID.
type OIDCIdentity struct {
	Provider      Provider
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	Nonce         string
	IssuedAt      time.Time
	Expiry        time.Time
	Claims        map[string]string
}

// Voucher binds an authenticated OIDC identity to a libp2p PeerID.
//
// It is serialized as a compact JWS using EdDSA (Ed25519), allowing offline
// verification without any callback to the issuing hub.
type Voucher struct {
	Token         string
	ID            string
	Issuer        string
	Audience      string
	Subject       string
	Provider      Provider
	PeerID        string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	Nonce         string
	IssuedAt      time.Time
	NotBefore     time.Time
	Expiry        time.Time
	Claims        map[string]string
}

// VoucherRequest requests issuance of a new signed voucher.
type VoucherRequest struct {
	Identity OIDCIdentity
	PeerID   string
	Audience string
	Nonce    string
	TTL      time.Duration
	Claims   map[string]string
}

// VerifyOptions constrains voucher validation for a specific connection or flow.
type VerifyOptions struct {
	ExpectedIssuer   string
	ExpectedAudience string
	ExpectedPeerID   string
	ExpectedNonce    string
	Now              time.Time
}

// IDTokenVerifier abstracts upstream OIDC token verification.
//
// A concrete implementation would typically fetch OIDC metadata and validate an
// ID token against the upstream provider. SAM keeps that concern abstract so the
// voucher format remains usable with Google, GitHub, or sovereign issuers.
type IDTokenVerifier interface {
	VerifyIDToken(ctx context.Context, rawToken string, expectedNonce string) (*OIDCIdentity, error)
}

// VoucherIssuer issues hub-signed vouchers that bind a verified identity to a PeerID.
type VoucherIssuer interface {
	Issue(ctx context.Context, req VoucherRequest) (string, error)
	Issuer() string
	PublicKey() ed25519.PublicKey
}

// VoucherVerifier validates a compact voucher and returns its decoded claims.
type VoucherVerifier interface {
	Verify(ctx context.Context, token string, opts VerifyOptions) (*Voucher, error)
}
