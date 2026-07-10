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
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

// VerifyJWT parses and cryptographically validates a JWT token against a list of allowed audiences
// and resolved OIDC providers.
func VerifyJWT(ctx context.Context, jwtStr string, allowedAudiences []string, providers map[string]*oidc.Provider) (jwt.MapClaims, *oidc.IDToken, error) {
	jwtParser := jwt.Parser{}
	jwtToken, _, err := jwtParser.ParseUnverified(jwtStr, jwt.MapClaims{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// 1. Defend against downgrade attacks immediately
	alg, ok := jwtToken.Header["alg"].(string)
	if !ok || alg == "" || strings.ToLower(alg) == "none" {
		return nil, nil, fmt.Errorf("invalid or missing alg header")
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, fmt.Errorf("invalid JWT claims")
	}
	iss, _ := claims["iss"].(string)

	// 2. Extract the audience
	var aud string
	switch a := claims["aud"].(type) {
	case string:
		aud = a
	case []any:
		if len(a) > 0 {
			aud, _ = a[0].(string)
		}
	}

	if aud == "" {
		return nil, nil, fmt.Errorf("missing aud claim")
	}

	// 3. Verify the audience matches one of your expected tenants/platforms
	validAudience := false
	for _, allowed := range allowedAudiences {
		if aud == allowed {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return nil, nil, fmt.Errorf("untrusted audience: %s", aud)
	}

	// 4. Route to the correct provider
	provider, ok := providers[iss]
	if !ok {
		return nil, nil, fmt.Errorf("unknown issuer: %s", iss)
	}

	// 5. Verify cryptographic signature, bypassing the strict single-clientID check
	// because we already validated the audience against our allowed list above.
	verifier := provider.Verifier(&oidc.Config{
		SkipClientIDCheck: true,
	})

	token, err := verifier.Verify(ctx, jwtStr)
	if err != nil {
		return nil, nil, fmt.Errorf("JWT validation failed: %w", err)
	}

	return claims, token, nil
}
