package economy

import (
	"context"
	"errors"
	"time"
)

// Micropayment contains normalized payment metadata extracted from request headers.
type Micropayment struct {
	Amount     int64
	Asset      string
	Nonce      string
	Payer      string
	Payee      string
	Capability string
}

// VerifyRequest is passed to a Biscuit verifier for offline authorization.
type VerifyRequest struct {
	Token   string
	Method  string
	Path    string
	Payment Micropayment
}

// VerifyDecision is returned by a verifier on successful authorization.
type VerifyDecision struct {
	Subject          string
	Policy           string
	AttenuationDepth int
	ExpiresAt        time.Time
	Metadata         map[string]string
}

// Verifier verifies Biscuit tokens and request-bound micropayment metadata.
type Verifier interface {
	Verify(ctx context.Context, req VerifyRequest) (*VerifyDecision, error)
}

var (
	ErrMissingBiscuitToken     = errors.New("missing Biscuit token header")
	ErrMissingMicropayAmount   = errors.New("missing micropayment amount header")
	ErrMissingMicropayAsset    = errors.New("missing micropayment asset header")
	ErrMissingMicropayNonce    = errors.New("missing micropayment nonce header")
	ErrInvalidMicropayAmount   = errors.New("invalid micropayment amount")
	ErrVerifierDeniedRequest   = errors.New("biscuit verifier denied request")
	ErrVerifierUnavailable     = errors.New("biscuit verifier unavailable")
	ErrMiddlewareMisconfigured = errors.New("economy middleware misconfigured")
)

// AllowAllVerifier is a Verifier that unconditionally approves every request.
// Useful for local development and bridges that do not require micropayment gating.
type AllowAllVerifier struct{}

func (AllowAllVerifier) Verify(_ context.Context, _ VerifyRequest) (*VerifyDecision, error) {
	return &VerifyDecision{Subject: "anonymous"}, nil
}
