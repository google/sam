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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

var (
	ErrInvalidVoucher   = errors.New("invalid voucher")
	ErrInvalidSignature = errors.New("invalid voucher signature")
	ErrUntrustedIssuer  = errors.New("untrusted voucher issuer")
	ErrVoucherExpired   = errors.New("voucher expired")
	ErrVoucherNotActive = errors.New("voucher not active")
)

type issuer struct {
	issuerName string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
	defaultTTL time.Duration
	clock      clock
}

type verifier struct {
	trustByIssuer map[string]trustedKey
	leeway        time.Duration
	clock         clock
}

type trustedKey struct {
	keyID     string
	publicKey ed25519.PublicKey
}

type voucherHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid,omitempty"`
}

type voucherClaims struct {
	Issuer        string            `json:"iss"`
	Subject       string            `json:"sub"`
	Audience      string            `json:"aud"`
	IssuedAt      int64             `json:"iat"`
	NotBefore     int64             `json:"nbf"`
	Expiry        int64             `json:"exp"`
	ID            string            `json:"jti"`
	Provider      Provider          `json:"provider"`
	PeerID        string            `json:"peer_id"`
	Email         string            `json:"email,omitempty"`
	EmailVerified bool              `json:"email_verified,omitempty"`
	Name          string            `json:"name,omitempty"`
	Picture       string            `json:"picture,omitempty"`
	Nonce         string            `json:"nonce,omitempty"`
	Claims        map[string]string `json:"claims,omitempty"`
}

// NewIssuer creates a voucher issuer backed by an Ed25519 signing key.
func NewIssuer(issuerName string, signingKey ed25519.PrivateKey, opts ...IssuerOption) (VoucherIssuer, error) {
	if issuerName == "" {
		return nil, fmt.Errorf("issuer name must not be empty")
	}
	if len(signingKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing key has invalid length")
	}

	i := &issuer{
		issuerName: issuerName,
		privateKey: append(ed25519.PrivateKey(nil), signingKey...),
		publicKey:  append(ed25519.PublicKey(nil), signingKey.Public().(ed25519.PublicKey)...),
		defaultTTL: defaultVoucherTTL,
		clock:      realClock{},
	}

	for _, opt := range opts {
		if err := opt(i); err != nil {
			return nil, fmt.Errorf("applying issuer option: %w", err)
		}
	}

	return i, nil
}

// NewVerifier creates a verifier with one or more trusted hub keys.
func NewVerifier(opts ...VerifierOption) (VoucherVerifier, error) {
	v := &verifier{
		trustByIssuer: make(map[string]trustedKey),
		leeway:        defaultLeeway,
		clock:         realClock{},
	}

	for _, opt := range opts {
		if err := opt(v); err != nil {
			return nil, fmt.Errorf("applying verifier option: %w", err)
		}
	}

	if len(v.trustByIssuer) == 0 {
		return nil, fmt.Errorf("at least one trusted issuer is required")
	}

	return v, nil
}

func (i *issuer) Issuer() string {
	return i.issuerName
}

func (i *issuer) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), i.publicKey...)
}

func (i *issuer) Issue(_ context.Context, req VoucherRequest) (string, error) {
	if err := validateOIDCIdentity(req.Identity); err != nil {
		return "", err
	}
	if err := validatePeerID(req.PeerID); err != nil {
		return "", err
	}
	if req.Audience == "" {
		return "", fmt.Errorf("audience must not be empty")
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = i.defaultTTL
	}
	if ttl <= 0 {
		return "", fmt.Errorf("voucher TTL must be positive")
	}

	now := i.clock.Now().UTC()
	nonce := req.Nonce
	if nonce == "" {
		nonce = req.Identity.Nonce
	}

	mergedClaims, err := mergeClaims(req.Identity.Claims, req.Claims)
	if err != nil {
		return "", err
	}

	claims := voucherClaims{
		Issuer:        i.issuerName,
		Subject:       req.Identity.Subject,
		Audience:      req.Audience,
		IssuedAt:      now.Unix(),
		NotBefore:     now.Unix(),
		Expiry:        now.Add(ttl).Unix(),
		ID:            randomID(),
		Provider:      req.Identity.Provider,
		PeerID:        req.PeerID,
		Email:         req.Identity.Email,
		EmailVerified: req.Identity.EmailVerified,
		Name:          req.Identity.Name,
		Picture:       req.Identity.Picture,
		Nonce:         nonce,
		Claims:        mergedClaims,
	}

	header := voucherHeader{
		Algorithm: "EdDSA",
		Type:      "JWT",
		KeyID:     i.keyID,
	}

	token, err := signJWT(header, claims, i.privateKey)
	if err != nil {
		return "", fmt.Errorf("signing voucher: %w", err)
	}

	return token, nil
}

func (v *verifier) Verify(_ context.Context, token string, opts VerifyOptions) (*Voucher, error) {
	header, claims, signingInput, sig, err := parseJWT(token)
	if err != nil {
		return nil, err
	}
	if header.Algorithm != "EdDSA" || header.Type != "JWT" {
		return nil, fmt.Errorf("%w: unsupported JOSE header", ErrInvalidVoucher)
	}

	trust, ok := v.trustByIssuer[claims.Issuer]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUntrustedIssuer, claims.Issuer)
	}
	if trust.keyID != "" && header.KeyID != "" && trust.keyID != header.KeyID {
		return nil, fmt.Errorf("%w: unexpected key id %q", ErrUntrustedIssuer, header.KeyID)
	}
	if !ed25519.Verify(trust.publicKey, []byte(signingInput), sig) {
		return nil, ErrInvalidSignature
	}

	if err := validatePeerID(claims.PeerID); err != nil {
		return nil, err
	}

	now := opts.Now.UTC()
	if now.IsZero() {
		now = v.clock.Now().UTC()
	}
	leeway := v.leeway

	issuedAt := time.Unix(claims.IssuedAt, 0).UTC()
	notBefore := time.Unix(claims.NotBefore, 0).UTC()
	expiry := time.Unix(claims.Expiry, 0).UTC()

	if now.After(expiry.Add(leeway)) {
		return nil, ErrVoucherExpired
	}
	if now.Before(notBefore.Add(-leeway)) {
		return nil, ErrVoucherNotActive
	}
	if claims.IssuedAt > 0 && now.Before(issuedAt.Add(-leeway)) {
		return nil, fmt.Errorf("%w: issued-at is in the future", ErrInvalidVoucher)
	}

	if opts.ExpectedIssuer != "" && opts.ExpectedIssuer != claims.Issuer {
		return nil, fmt.Errorf("%w: issuer mismatch", ErrInvalidVoucher)
	}
	if opts.ExpectedAudience != "" && opts.ExpectedAudience != claims.Audience {
		return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidVoucher)
	}
	if opts.ExpectedPeerID != "" && opts.ExpectedPeerID != claims.PeerID {
		return nil, fmt.Errorf("%w: peer ID mismatch", ErrInvalidVoucher)
	}
	if opts.ExpectedNonce != "" && opts.ExpectedNonce != claims.Nonce {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrInvalidVoucher)
	}

	return &Voucher{
		Token:         token,
		ID:            claims.ID,
		Issuer:        claims.Issuer,
		Audience:      claims.Audience,
		Subject:       claims.Subject,
		Provider:      claims.Provider,
		PeerID:        claims.PeerID,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		Picture:       claims.Picture,
		Nonce:         claims.Nonce,
		IssuedAt:      issuedAt,
		NotBefore:     notBefore,
		Expiry:        expiry,
		Claims:        copyClaims(claims.Claims),
	}, nil
}

func signJWT(header voucherHeader, claims voucherClaims, privateKey ed25519.PrivateKey) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling JOSE header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshaling voucher claims: %w", err)
	}

	head := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := head + "." + payload
	signature := ed25519.Sign(privateKey, []byte(signingInput))

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func parseJWT(token string) (voucherHeader, voucherClaims, string, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return voucherHeader{}, voucherClaims{}, "", nil, fmt.Errorf("%w: compact token must have three parts", ErrInvalidVoucher)
	}

	var header voucherHeader
	if err := decodeSegment(parts[0], &header); err != nil {
		return voucherHeader{}, voucherClaims{}, "", nil, fmt.Errorf("%w: invalid JOSE header: %v", ErrInvalidVoucher, err)
	}
	var claims voucherClaims
	if err := decodeSegment(parts[1], &claims); err != nil {
		return voucherHeader{}, voucherClaims{}, "", nil, fmt.Errorf("%w: invalid claims set: %v", ErrInvalidVoucher, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return voucherHeader{}, voucherClaims{}, "", nil, fmt.Errorf("%w: invalid signature encoding", ErrInvalidVoucher)
	}

	return header, claims, parts[0] + "." + parts[1], sig, nil
}

func decodeSegment(segment string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func validateOIDCIdentity(identity OIDCIdentity) error {
	if identity.Provider == "" {
		return fmt.Errorf("provider must not be empty")
	}
	if identity.Issuer == "" {
		return fmt.Errorf("upstream issuer must not be empty")
	}
	if identity.Subject == "" {
		return fmt.Errorf("subject must not be empty")
	}
	return nil
}

func validatePeerID(peerID string) error {
	if peerID == "" {
		return fmt.Errorf("peer ID must not be empty")
	}
	if _, err := peer.Decode(peerID); err != nil {
		return fmt.Errorf("invalid peer ID %q: %w", peerID, err)
	}
	return nil
}

func mergeClaims(identityClaims, requestClaims map[string]string) (map[string]string, error) {
	merged := copyClaims(identityClaims)
	for key, value := range requestClaims {
		if isReservedClaim(key) {
			return nil, fmt.Errorf("claim %q is reserved", key)
		}
		merged[key] = value
	}
	if len(merged) == 0 {
		return nil, nil
	}
	return merged, nil
}

func copyClaims(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func isReservedClaim(key string) bool {
	switch key {
	case "iss", "sub", "aud", "iat", "nbf", "exp", "jti", "provider", "peer_id", "email", "email_verified", "name", "picture", "nonce", "claims":
		return true
	default:
		return false
	}
}

func randomID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
