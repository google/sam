package identity

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

const (
	defaultVoucherTTL = 15 * time.Minute
	defaultLeeway     = 30 * time.Second
)

type clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now().UTC()
}

// TrustedIssuer is a verifier-side trust anchor.
type TrustedIssuer struct {
	Issuer    string
	KeyID     string
	PublicKey ed25519.PublicKey
}

// IssuerOption customizes a voucher issuer.
type IssuerOption func(*issuer) error

// VerifierOption customizes a voucher verifier.
type VerifierOption func(*verifier) error

// WithIssuerKeyID attaches a key identifier to signed vouchers.
func WithIssuerKeyID(keyID string) IssuerOption {
	return func(i *issuer) error {
		i.keyID = keyID
		return nil
	}
}

// WithIssuerDefaultTTL overrides the default voucher TTL.
func WithIssuerDefaultTTL(ttl time.Duration) IssuerOption {
	return func(i *issuer) error {
		if ttl <= 0 {
			return fmt.Errorf("default TTL must be positive")
		}
		i.defaultTTL = ttl
		return nil
	}
}

// WithIssuerClock injects a deterministic clock for tests.
func WithIssuerClock(c clock) IssuerOption {
	return func(i *issuer) error {
		if c == nil {
			return fmt.Errorf("issuer clock must not be nil")
		}
		i.clock = c
		return nil
	}
}

// WithTrustedIssuer registers a trusted issuer key on the verifier.
func WithTrustedIssuer(issuerName string, key ed25519.PublicKey) VerifierOption {
	return func(v *verifier) error {
		if issuerName == "" {
			return fmt.Errorf("trusted issuer name must not be empty")
		}
		if len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("trusted issuer public key has invalid length")
		}
		v.trustByIssuer[issuerName] = trustedKey{publicKey: append(ed25519.PublicKey(nil), key...)}
		return nil
	}
}

// WithTrustedIssuerRecord registers a trusted issuer key with an optional key ID.
func WithTrustedIssuerRecord(record TrustedIssuer) VerifierOption {
	return func(v *verifier) error {
		if record.Issuer == "" {
			return fmt.Errorf("trusted issuer name must not be empty")
		}
		if len(record.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("trusted issuer public key has invalid length")
		}
		v.trustByIssuer[record.Issuer] = trustedKey{
			keyID:     record.KeyID,
			publicKey: append(ed25519.PublicKey(nil), record.PublicKey...),
		}
		return nil
	}
}

// WithVerifierClock injects a deterministic clock for tests.
func WithVerifierClock(c clock) VerifierOption {
	return func(v *verifier) error {
		if c == nil {
			return fmt.Errorf("verifier clock must not be nil")
		}
		v.clock = c
		return nil
	}
}

// WithVerifierLeeway sets the time skew tolerance for exp/nbf/iat checks.
func WithVerifierLeeway(leeway time.Duration) VerifierOption {
	return func(v *verifier) error {
		if leeway < 0 {
			return fmt.Errorf("verifier leeway must not be negative")
		}
		v.leeway = leeway
		return nil
	}
}
