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
