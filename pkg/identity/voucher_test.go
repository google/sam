package identity_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"sam/pkg/identity"
)

type fixedClock struct {
	now time.Time
}

func (f fixedClock) Now() time.Time {
	return f.now
}

func TestVoucherIssueAndVerify(t *testing.T) {
	issuedAt := time.Date(2026, 4, 17, 23, 50, 0, 0, time.UTC)
	issuerKey := generateSigningKey(t)
	peerID := generatePeerID(t)

	issuer, err := identity.NewIssuer(
		"hub.sam.dev",
		issuerKey,
		identity.WithIssuerKeyID("hub-key-1"),
		identity.WithIssuerDefaultTTL(10*time.Minute),
		identity.WithIssuerClock(fixedClock{now: issuedAt}),
	)
	if err != nil {
		t.Fatalf("NewIssuer() error = %v", err)
	}

	verifier, err := identity.NewVerifier(
		identity.WithTrustedIssuerRecord(identity.TrustedIssuer{
			Issuer:    issuer.Issuer(),
			KeyID:     "hub-key-1",
			PublicKey: issuer.PublicKey(),
		}),
		identity.WithVerifierClock(fixedClock{now: issuedAt.Add(2 * time.Minute)}),
	)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	token, err := issuer.Issue(context.Background(), identity.VoucherRequest{
		PeerID:   peerID,
		Audience: "sam://mesh/bootstrap",
		Nonce:    "nonce-123",
		Identity: identity.OIDCIdentity{
			Provider:      identity.ProviderGoogle,
			Issuer:        "https://accounts.google.com",
			Subject:       "user-123",
			Email:         "agent@example.com",
			EmailVerified: true,
			Name:          "Agent Smith",
			Picture:       "https://example.com/avatar.png",
			Claims: map[string]string{
				"tenant": "example",
			},
		},
		Claims: map[string]string{
			"role": "executor",
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	voucher, err := verifier.Verify(context.Background(), token, identity.VerifyOptions{
		ExpectedIssuer:   "hub.sam.dev",
		ExpectedAudience: "sam://mesh/bootstrap",
		ExpectedPeerID:   peerID,
		ExpectedNonce:    "nonce-123",
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if voucher.Issuer != "hub.sam.dev" {
		t.Fatalf("voucher issuer = %q, want %q", voucher.Issuer, "hub.sam.dev")
	}
	if voucher.Subject != "user-123" {
		t.Fatalf("voucher subject = %q, want %q", voucher.Subject, "user-123")
	}
	if voucher.PeerID != peerID {
		t.Fatalf("voucher peer ID = %q, want %q", voucher.PeerID, peerID)
	}
	if voucher.Provider != identity.ProviderGoogle {
		t.Fatalf("voucher provider = %q, want %q", voucher.Provider, identity.ProviderGoogle)
	}
	if voucher.Claims["tenant"] != "example" || voucher.Claims["role"] != "executor" {
		t.Fatalf("voucher claims = %#v, want merged tenant and role", voucher.Claims)
	}
	if voucher.Expiry.Sub(voucher.IssuedAt) != 10*time.Minute {
		t.Fatalf("voucher TTL = %s, want %s", voucher.Expiry.Sub(voucher.IssuedAt), 10*time.Minute)
	}
}

func TestIssueRejectsInvalidInput(t *testing.T) {
	issuerKey := generateSigningKey(t)
	issuer, err := identity.NewIssuer("hub.sam.dev", issuerKey)
	if err != nil {
		t.Fatalf("NewIssuer() error = %v", err)
	}

	tests := []struct {
		name    string
		req     identity.VoucherRequest
		wantErr string
	}{
		{
			name: "missing provider",
			req: identity.VoucherRequest{
				PeerID:   generatePeerID(t),
				Audience: "sam://mesh",
				Identity: identity.OIDCIdentity{Issuer: "https://accounts.google.com", Subject: "sub"},
			},
			wantErr: "provider must not be empty",
		},
		{
			name: "invalid peer id",
			req: identity.VoucherRequest{
				PeerID:   "not-a-peer-id",
				Audience: "sam://mesh",
				Identity: identity.OIDCIdentity{Provider: identity.ProviderGoogle, Issuer: "https://accounts.google.com", Subject: "sub"},
			},
			wantErr: "invalid peer ID",
		},
		{
			name: "missing audience",
			req: identity.VoucherRequest{
				PeerID:   generatePeerID(t),
				Identity: identity.OIDCIdentity{Provider: identity.ProviderGoogle, Issuer: "https://accounts.google.com", Subject: "sub"},
			},
			wantErr: "audience must not be empty",
		},
		{
			name: "reserved claim rejected",
			req: identity.VoucherRequest{
				PeerID:   generatePeerID(t),
				Audience: "sam://mesh",
				Identity: identity.OIDCIdentity{Provider: identity.ProviderGoogle, Issuer: "https://accounts.google.com", Subject: "sub"},
				Claims:   map[string]string{"iss": "forbidden"},
			},
			wantErr: "reserved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := issuer.Issue(context.Background(), tt.req)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Issue() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyFailures(t *testing.T) {
	baseTime := time.Date(2026, 4, 17, 23, 55, 0, 0, time.UTC)
	issuerKey := generateSigningKey(t)
	issuer, err := identity.NewIssuer(
		"hub.sam.dev",
		issuerKey,
		identity.WithIssuerClock(fixedClock{now: baseTime}),
	)
	if err != nil {
		t.Fatalf("NewIssuer() error = %v", err)
	}
	peerID := generatePeerID(t)
	token, err := issuer.Issue(context.Background(), identity.VoucherRequest{
		PeerID:   peerID,
		Audience: "sam://mesh/bootstrap",
		Nonce:    "nonce-abc",
		TTL:      5 * time.Minute,
		Identity: identity.OIDCIdentity{
			Provider: identity.ProviderGoogle,
			Issuer:   "https://accounts.google.com",
			Subject:  "user-123",
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	tests := []struct {
		name     string
		token    string
		options  identity.VerifyOptions
		verifier identity.VoucherVerifier
		wantErr  error
	}{
		{
			name:  "untrusted issuer",
			token: token,
			verifier: mustVerifier(t,
				identity.WithTrustedIssuer("other.sam.dev", generateSigningKey(t).Public().(ed25519.PublicKey)),
				identity.WithVerifierClock(fixedClock{now: baseTime.Add(time.Minute)}),
			),
			wantErr: identity.ErrUntrustedIssuer,
		},
		{
			name: "tampered signature",
			token: func() string {
				parts := strings.Split(token, ".")
				if len(parts) != 3 || len(parts[2]) == 0 {
					return token + "tampered"
				}
				if parts[2][0] == 'A' {
					parts[2] = "B" + parts[2][1:]
				} else {
					parts[2] = "A" + parts[2][1:]
				}
				return strings.Join(parts, ".")
			}(),
			verifier: mustVerifier(t,
				identity.WithTrustedIssuer("hub.sam.dev", issuer.PublicKey()),
				identity.WithVerifierClock(fixedClock{now: baseTime.Add(time.Minute)}),
			),
			wantErr: identity.ErrInvalidSignature,
		},
		{
			name:  "expired voucher",
			token: token,
			verifier: mustVerifier(t,
				identity.WithTrustedIssuer("hub.sam.dev", issuer.PublicKey()),
				identity.WithVerifierClock(fixedClock{now: baseTime.Add(6 * time.Minute)}),
				identity.WithVerifierLeeway(0),
			),
			wantErr: identity.ErrVoucherExpired,
		},
		{
			name:  "peer mismatch",
			token: token,
			verifier: mustVerifier(t,
				identity.WithTrustedIssuer("hub.sam.dev", issuer.PublicKey()),
				identity.WithVerifierClock(fixedClock{now: baseTime.Add(time.Minute)}),
			),
			options: identity.VerifyOptions{ExpectedPeerID: generatePeerID(t)},
			wantErr: identity.ErrInvalidVoucher,
		},
		{
			name:  "audience mismatch",
			token: token,
			verifier: mustVerifier(t,
				identity.WithTrustedIssuer("hub.sam.dev", issuer.PublicKey()),
				identity.WithVerifierClock(fixedClock{now: baseTime.Add(time.Minute)}),
			),
			options: identity.VerifyOptions{ExpectedAudience: "sam://mesh/other"},
			wantErr: identity.ErrInvalidVoucher,
		},
		{
			name:  "nonce mismatch",
			token: token,
			verifier: mustVerifier(t,
				identity.WithTrustedIssuer("hub.sam.dev", issuer.PublicKey()),
				identity.WithVerifierClock(fixedClock{now: baseTime.Add(time.Minute)}),
			),
			options: identity.VerifyOptions{ExpectedNonce: "wrong"},
			wantErr: identity.ErrInvalidVoucher,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.verifier.Verify(context.Background(), tt.token, tt.options)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr.Error()) {
				t.Fatalf("Verify() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyLeeway(t *testing.T) {
	baseTime := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)
	issuerKey := generateSigningKey(t)
	issuer, err := identity.NewIssuer(
		"hub.sam.dev",
		issuerKey,
		identity.WithIssuerClock(fixedClock{now: baseTime}),
	)
	if err != nil {
		t.Fatalf("NewIssuer() error = %v", err)
	}

	token, err := issuer.Issue(context.Background(), identity.VoucherRequest{
		PeerID:   generatePeerID(t),
		Audience: "sam://mesh/bootstrap",
		TTL:      1 * time.Minute,
		Identity: identity.OIDCIdentity{
			Provider: identity.ProviderGoogle,
			Issuer:   "https://accounts.google.com",
			Subject:  "user-123",
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	verifier := mustVerifier(t,
		identity.WithTrustedIssuer("hub.sam.dev", issuer.PublicKey()),
		identity.WithVerifierClock(fixedClock{now: baseTime.Add(65 * time.Second)}),
		identity.WithVerifierLeeway(10*time.Second),
	)

	if _, err := verifier.Verify(context.Background(), token, identity.VerifyOptions{}); err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
}

func mustVerifier(t *testing.T, opts ...identity.VerifierOption) identity.VoucherVerifier {
	t.Helper()
	v, err := identity.NewVerifier(opts...)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	return v
}

func generateSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return key
}

func generatePeerID(t *testing.T) string {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey() error = %v", err)
	}
	return id.String()
}
