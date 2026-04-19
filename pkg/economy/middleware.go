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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var tracer = otel.Tracer("sam/economy")

const (
	DefaultBiscuitTokenHeader       = "X-SAM-Biscuit"
	DefaultMicropaymentAmountHeader = "X-SAM-Micropayment-Amount"
	DefaultMicropaymentAssetHeader  = "X-SAM-Micropayment-Asset"
	DefaultMicropaymentNonceHeader  = "X-SAM-Micropayment-Nonce"
	DefaultMicropaymentPayerHeader  = "X-SAM-Micropayment-Payer"
	DefaultMicropaymentPayeeHeader  = "X-SAM-Micropayment-Payee"
	DefaultA2ACapabilityHeader      = "X-SAM-A2A-Capability"
)

type contextKey string

const (
	decisionContextKey contextKey = "sam.economy.decision"
	paymentContextKey  contextKey = "sam.economy.payment"
)

// Middleware validates Biscuit-based micropayment headers for A2A requests.
type Middleware struct {
	verifier Verifier
	opts     Options
}

// Options controls middleware behavior and wire format.
type Options struct {
	TokenHeader      string
	AmountHeader     string
	AssetHeader      string
	NonceHeader      string
	PayerHeader      string
	PayeeHeader      string
	CapabilityHeader string
}

// Option mutates middleware options.
type Option func(*Options)

// DefaultOptions returns production-safe defaults.
func DefaultOptions() Options {
	return Options{
		TokenHeader:      DefaultBiscuitTokenHeader,
		AmountHeader:     DefaultMicropaymentAmountHeader,
		AssetHeader:      DefaultMicropaymentAssetHeader,
		NonceHeader:      DefaultMicropaymentNonceHeader,
		PayerHeader:      DefaultMicropaymentPayerHeader,
		PayeeHeader:      DefaultMicropaymentPayeeHeader,
		CapabilityHeader: DefaultA2ACapabilityHeader,
	}
}

// WithTokenHeader configures the Biscuit token header.
func WithTokenHeader(name string) Option {
	return func(o *Options) { o.TokenHeader = name }
}

// WithAmountHeader configures the micropayment amount header.
func WithAmountHeader(name string) Option {
	return func(o *Options) { o.AmountHeader = name }
}

// WithAssetHeader configures the micropayment asset header.
func WithAssetHeader(name string) Option {
	return func(o *Options) { o.AssetHeader = name }
}

// WithNonceHeader configures the micropayment nonce header.
func WithNonceHeader(name string) Option {
	return func(o *Options) { o.NonceHeader = name }
}

// WithPayerHeader configures the micropayment payer header.
func WithPayerHeader(name string) Option {
	return func(o *Options) { o.PayerHeader = name }
}

// WithPayeeHeader configures the micropayment payee header.
func WithPayeeHeader(name string) Option {
	return func(o *Options) { o.PayeeHeader = name }
}

// WithCapabilityHeader configures the A2A capability header.
func WithCapabilityHeader(name string) Option {
	return func(o *Options) { o.CapabilityHeader = name }
}

// NewMiddleware creates a new Biscuit middleware for inbound A2A requests.
func NewMiddleware(verifier Verifier, opts ...Option) (*Middleware, error) {
	if verifier == nil {
		return nil, fmt.Errorf("%w: verifier is nil", ErrMiddlewareMisconfigured)
	}

	o := DefaultOptions()
	for _, fn := range opts {
		fn(&o)
	}

	if err := o.validate(); err != nil {
		return nil, err
	}

	return &Middleware{verifier: verifier, opts: o}, nil
}

// Wrap applies Biscuit verification to each inbound request.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tracer.Start(r.Context(), "economy.middleware",
			trace.WithAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.path", r.URL.Path),
			),
		)
		defer span.End()

		token, payment, err := m.extract(r)
		if err != nil {
			span.RecordError(err)
			writeError(w, statusForExtractError(err), err)
			return
		}

		span.SetAttributes(
			attribute.Int64("sam.payment.amount", payment.Amount),
			attribute.String("sam.payment.asset", payment.Asset),
			attribute.String("sam.a2a.capability", payment.Capability),
		)

		decision, err := m.verifier.Verify(ctx, VerifyRequest{
			Token:   token,
			Method:  r.Method,
			Path:    r.URL.Path,
			Payment: payment,
		})
		if err != nil {
			span.RecordError(err)
			status := http.StatusPaymentRequired
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				status = http.StatusGatewayTimeout
			}
			writeError(w, status, fmt.Errorf("%w: %v", ErrVerifierDeniedRequest, err))
			return
		}

		span.SetAttributes(
			attribute.String("sam.auth.subject", decision.Subject),
			attribute.Int("sam.auth.attenuation_depth", decision.AttenuationDepth),
		)

		ctx = context.WithValue(ctx, paymentContextKey, payment)
		ctx = context.WithValue(ctx, decisionContextKey, decision)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// DecisionFromContext retrieves a verifier decision placed by middleware.
func DecisionFromContext(ctx context.Context) (*VerifyDecision, bool) {
	v, ok := ctx.Value(decisionContextKey).(*VerifyDecision)
	return v, ok
}

// MicropaymentFromContext retrieves normalized payment metadata from request context.
func MicropaymentFromContext(ctx context.Context) (Micropayment, bool) {
	v, ok := ctx.Value(paymentContextKey).(Micropayment)
	return v, ok
}

func (m *Middleware) extract(r *http.Request) (string, Micropayment, error) {
	token := strings.TrimSpace(r.Header.Get(m.opts.TokenHeader))
	if token == "" {
		return "", Micropayment{}, ErrMissingBiscuitToken
	}

	amountRaw := strings.TrimSpace(r.Header.Get(m.opts.AmountHeader))
	if amountRaw == "" {
		return "", Micropayment{}, ErrMissingMicropayAmount
	}
	amount, err := strconv.ParseInt(amountRaw, 10, 64)
	if err != nil || amount <= 0 {
		return "", Micropayment{}, ErrInvalidMicropayAmount
	}

	asset := strings.TrimSpace(r.Header.Get(m.opts.AssetHeader))
	if asset == "" {
		return "", Micropayment{}, ErrMissingMicropayAsset
	}

	nonce := strings.TrimSpace(r.Header.Get(m.opts.NonceHeader))
	if nonce == "" {
		return "", Micropayment{}, ErrMissingMicropayNonce
	}

	payment := Micropayment{
		Amount:     amount,
		Asset:      asset,
		Nonce:      nonce,
		Payer:      strings.TrimSpace(r.Header.Get(m.opts.PayerHeader)),
		Payee:      strings.TrimSpace(r.Header.Get(m.opts.PayeeHeader)),
		Capability: strings.TrimSpace(r.Header.Get(m.opts.CapabilityHeader)),
	}

	return token, payment, nil
}

func (o Options) validate() error {
	if strings.TrimSpace(o.TokenHeader) == "" {
		return fmt.Errorf("%w: token header is required", ErrMiddlewareMisconfigured)
	}
	if strings.TrimSpace(o.AmountHeader) == "" {
		return fmt.Errorf("%w: amount header is required", ErrMiddlewareMisconfigured)
	}
	if strings.TrimSpace(o.AssetHeader) == "" {
		return fmt.Errorf("%w: asset header is required", ErrMiddlewareMisconfigured)
	}
	if strings.TrimSpace(o.NonceHeader) == "" {
		return fmt.Errorf("%w: nonce header is required", ErrMiddlewareMisconfigured)
	}
	if strings.TrimSpace(o.PayerHeader) == "" {
		return fmt.Errorf("%w: payer header is required", ErrMiddlewareMisconfigured)
	}
	if strings.TrimSpace(o.PayeeHeader) == "" {
		return fmt.Errorf("%w: payee header is required", ErrMiddlewareMisconfigured)
	}
	if strings.TrimSpace(o.CapabilityHeader) == "" {
		return fmt.Errorf("%w: capability header is required", ErrMiddlewareMisconfigured)
	}
	return nil
}

func statusForExtractError(err error) int {
	if errors.Is(err, ErrMissingBiscuitToken) {
		return http.StatusUnauthorized
	}
	return http.StatusBadRequest
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: err.Error()})
}
