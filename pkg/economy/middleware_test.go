package economy_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sam/pkg/economy"
)

type fakeVerifier struct {
	decision *economy.VerifyDecision
	err      error
	lastReq  economy.VerifyRequest
	called   bool
}

func (f *fakeVerifier) Verify(_ context.Context, req economy.VerifyRequest) (*economy.VerifyDecision, error) {
	f.called = true
	f.lastReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.decision, nil
}

func TestMiddlewareRejectsMissingHeaders(t *testing.T) {
	tests := []struct {
		name         string
		headers      map[string]string
		wantStatus   int
		wantErrSub   string
		verifierCall bool
	}{
		{
			name:       "missing token",
			headers:    validHeaders(),
			wantStatus: http.StatusUnauthorized,
			wantErrSub: economy.ErrMissingBiscuitToken.Error(),
		},
		{
			name:       "missing amount",
			headers:    drop(validHeaders(), economy.DefaultMicropaymentAmountHeader),
			wantStatus: http.StatusBadRequest,
			wantErrSub: economy.ErrMissingMicropayAmount.Error(),
		},
		{
			name:       "invalid amount",
			headers:    set(validHeaders(), economy.DefaultMicropaymentAmountHeader, "abc"),
			wantStatus: http.StatusBadRequest,
			wantErrSub: economy.ErrInvalidMicropayAmount.Error(),
		},
		{
			name:       "missing asset",
			headers:    drop(validHeaders(), economy.DefaultMicropaymentAssetHeader),
			wantStatus: http.StatusBadRequest,
			wantErrSub: economy.ErrMissingMicropayAsset.Error(),
		},
		{
			name:       "missing nonce",
			headers:    drop(validHeaders(), economy.DefaultMicropaymentNonceHeader),
			wantStatus: http.StatusBadRequest,
			wantErrSub: economy.ErrMissingMicropayNonce.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &fakeVerifier{decision: &economy.VerifyDecision{Subject: "peer:alice"}}
			mw, err := economy.NewMiddleware(v)
			if err != nil {
				t.Fatalf("NewMiddleware() error = %v", err)
			}

			h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))

			req := httptest.NewRequest(http.MethodPost, "/a2a/call", nil)
			for k, val := range tt.headers {
				req.Header.Set(k, val)
			}
			if tt.name == "missing token" {
				req.Header.Del(economy.DefaultBiscuitTokenHeader)
			}

			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
			if !strings.Contains(rr.Body.String(), tt.wantErrSub) {
				t.Fatalf("body = %q, want substring %q", rr.Body.String(), tt.wantErrSub)
			}
			if v.called {
				t.Fatal("verifier should not be called for malformed requests")
			}
		})
	}
}

func TestMiddlewarePassesDecisionAndPaymentInContext(t *testing.T) {
	v := &fakeVerifier{decision: &economy.VerifyDecision{Subject: "peer:alice", AttenuationDepth: 2}}
	mw, err := economy.NewMiddleware(v)
	if err != nil {
		t.Fatalf("NewMiddleware() error = %v", err)
	}

	called := false
	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true

		decision, ok := economy.DecisionFromContext(r.Context())
		if !ok {
			t.Fatal("decision missing from context")
		}
		if decision.Subject != "peer:alice" {
			t.Fatalf("decision subject = %q, want %q", decision.Subject, "peer:alice")
		}

		payment, ok := economy.MicropaymentFromContext(r.Context())
		if !ok {
			t.Fatal("payment missing from context")
		}
		if payment.Amount != 42 || payment.Asset != "sam-credit" || payment.Nonce != "n-1" {
			t.Fatalf("unexpected payment = %#v", payment)
		}

		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodPost, "/a2a/call", nil)
	for k, val := range validHeaders() {
		req.Header.Set(k, val)
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatal("next handler was not called")
	}
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
	if !v.called {
		t.Fatal("verifier was not called")
	}
	if v.lastReq.Token != "biscuit-token" {
		t.Fatalf("token = %q, want %q", v.lastReq.Token, "biscuit-token")
	}
	if v.lastReq.Payment.Capability != "agent.chat" {
		t.Fatalf("capability = %q, want %q", v.lastReq.Payment.Capability, "agent.chat")
	}
}

func TestMiddlewareMapsVerifierFailure(t *testing.T) {
	v := &fakeVerifier{err: errors.New("insufficient funds")}
	mw, err := economy.NewMiddleware(v)
	if err != nil {
		t.Fatalf("NewMiddleware() error = %v", err)
	}

	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/a2a/call", nil)
	for k, val := range validHeaders() {
		req.Header.Set(k, val)
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusPaymentRequired)
	}
	if !strings.Contains(rr.Body.String(), economy.ErrVerifierDeniedRequest.Error()) {
		t.Fatalf("body = %q, want substring %q", rr.Body.String(), economy.ErrVerifierDeniedRequest.Error())
	}
}

func TestNewMiddlewareValidation(t *testing.T) {
	if _, err := economy.NewMiddleware(nil); !errors.Is(err, economy.ErrMiddlewareMisconfigured) {
		t.Fatalf("NewMiddleware(nil) error = %v, want ErrMiddlewareMisconfigured", err)
	}

	v := &fakeVerifier{decision: &economy.VerifyDecision{Subject: "peer:alice"}}
	if _, err := economy.NewMiddleware(v, economy.WithTokenHeader("")); !errors.Is(err, economy.ErrMiddlewareMisconfigured) {
		t.Fatalf("NewMiddleware(empty header) error = %v, want ErrMiddlewareMisconfigured", err)
	}
}

func validHeaders() map[string]string {
	return map[string]string{
		economy.DefaultBiscuitTokenHeader:       "biscuit-token",
		economy.DefaultMicropaymentAmountHeader: "42",
		economy.DefaultMicropaymentAssetHeader:  "sam-credit",
		economy.DefaultMicropaymentNonceHeader:  "n-1",
		economy.DefaultMicropaymentPayerHeader:  "peer:alice",
		economy.DefaultMicropaymentPayeeHeader:  "peer:bob",
		economy.DefaultA2ACapabilityHeader:      "agent.chat",
	}
}

func drop(headers map[string]string, key string) map[string]string {
	cloned := make(map[string]string, len(headers))
	for k, v := range headers {
		cloned[k] = v
	}
	delete(cloned, key)
	return cloned
}

func set(headers map[string]string, key, val string) map[string]string {
	cloned := make(map[string]string, len(headers))
	for k, v := range headers {
		cloned[k] = v
	}
	cloned[key] = val
	return cloned
}
