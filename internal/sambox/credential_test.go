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

package sambox

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testKID = "test-key"

// newMockPlatformIssuer stands in for a Kubernetes API server issuing projected
// service-account tokens.
func newMockPlatformIssuer(t *testing.T) (issuer string, key *rsa.PrivateKey) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   issuer,
			"jwks_uri": issuer + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": testKID,
				"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
			}},
		})
	})

	return issuer, privKey
}

func signCredential(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKID
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

// bundleWithCredential writes a bundle and its credential file, returning the
// loaded bundle.
func bundleWithCredential(t *testing.T, externalID, credential string) *AgentBundle {
	t.Helper()

	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "token")
	if credential != "" {
		if err := os.WriteFile(credentialPath, []byte(credential), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	content := "version: v1\nagent:\n  id: reviewer-7.prod.acme.example\n"
	if externalID != "" {
		content += "  external_id: " + externalID + "\n"
	}
	if credential != "" {
		content += "  credential: " + credentialPath + "\n"
	}

	bundle, err := LoadAgentBundle(writeBundle(t, content))
	if err != nil {
		t.Fatalf("LoadAgentBundle: %v", err)
	}
	return bundle
}

func TestWorkloadVerifier(t *testing.T) {
	issuer, key := newMockPlatformIssuer(t)
	ctx := context.Background()

	verifier, err := NewWorkloadVerifier(ctx, issuer, "sam-mesh")
	if err != nil {
		t.Fatalf("NewWorkloadVerifier: %v", err)
	}

	subject := "system:serviceaccount:prod:reviewer"
	valid := jwt.MapClaims{
		"iss": issuer,
		"aud": "sam-mesh",
		"sub": subject,
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	t.Run("a credential attesting the declared identity", func(t *testing.T) {
		bundle := bundleWithCredential(t, subject, signCredential(t, key, valid))
		if err := verifier.Verify(ctx, bundle); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})

	// The one that matters. Every sandbox on a platform holds a valid
	// credential, so a signature check alone would let any of them claim to be
	// any other.
	t.Run("a valid credential for somebody else", func(t *testing.T) {
		other := signCredential(t, key, jwt.MapClaims{
			"iss": issuer,
			"aud": "sam-mesh",
			"sub": "system:serviceaccount:prod:some-other-workload",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		bundle := bundleWithCredential(t, subject, other)

		err := verifier.Verify(ctx, bundle)
		if err == nil {
			t.Fatal("Verify accepted a credential attesting a different workload")
		}
		if !strings.Contains(err.Error(), "some-other-workload") {
			t.Errorf("error = %v, want it to name the subject actually attested", err)
		}
	})

	t.Run("rejections", func(t *testing.T) {
		otherIssuer, otherKey := newMockPlatformIssuer(t)

		tests := []struct {
			name       string
			externalID string
			credential string
		}{
			{
				name:       "expired",
				externalID: subject,
				credential: signCredential(t, key, jwt.MapClaims{
					"iss": issuer, "aud": "sam-mesh", "sub": subject,
					"exp": time.Now().Add(-time.Minute).Unix(),
				}),
			},
			{
				name:       "for a different audience",
				externalID: subject,
				credential: signCredential(t, key, jwt.MapClaims{
					"iss": issuer, "aud": "somebody-else", "sub": subject,
					"exp": time.Now().Add(time.Hour).Unix(),
				}),
			},
			{
				// An issuer the operator did not name. This is why the issuer
				// cannot come from the bundle: an attacker who chose it would
				// simply sign their own.
				name:       "from an issuer this gateway does not trust",
				externalID: subject,
				credential: signCredential(t, otherKey, jwt.MapClaims{
					"iss": otherIssuer, "aud": "sam-mesh", "sub": subject,
					"exp": time.Now().Add(time.Hour).Unix(),
				}),
			},
			{
				name:       "signed by the wrong key for the right issuer",
				externalID: subject,
				credential: signCredential(t, otherKey, valid),
			},
			{
				name:       "not a token at all",
				externalID: subject,
				credential: "not-a-jwt",
			},
			{
				name:       "attesting no subject",
				externalID: subject,
				credential: signCredential(t, key, jwt.MapClaims{
					"iss": issuer, "aud": "sam-mesh",
					"exp": time.Now().Add(time.Hour).Unix(),
				}),
			},
			{
				name:       "declared without an external identity to attest",
				credential: signCredential(t, key, valid),
			},
			{
				name:       "no credential at all",
				externalID: subject,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				bundle := bundleWithCredential(t, tc.externalID, tc.credential)
				if err := verifier.Verify(ctx, bundle); err == nil {
					t.Fatal("Verify accepted it, want an error")
				}
			})
		}
	})
}

func TestNewWorkloadVerifierRequiresIssuerAndAudience(t *testing.T) {
	ctx := context.Background()
	issuer, _ := newMockPlatformIssuer(t)

	if _, err := NewWorkloadVerifier(ctx, "", "sam-mesh"); err == nil {
		t.Error("NewWorkloadVerifier accepted an empty issuer")
	}
	if _, err := NewWorkloadVerifier(ctx, issuer, ""); err == nil {
		t.Error("NewWorkloadVerifier accepted an empty audience")
	}
	if _, err := NewWorkloadVerifier(ctx, "http://127.0.0.1:1/not-an-issuer", "sam-mesh"); err == nil {
		t.Error("NewWorkloadVerifier accepted an unreachable issuer, want it to fail at startup")
	}
}
