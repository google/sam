package integration_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func startMockOIDC(t *testing.T) (string, string) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	issuer := srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":   issuer,
			"jwks_uri": issuer + "/keys",
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": "mock-key",
					"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
				},
			},
		})
	})

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer,
		"aud": "sam-mesh-audience",
		"sub": "mock-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "mock-key"
	jwtStr, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed to sign jwt: %v", err)
	}

	return issuer, jwtStr
}
