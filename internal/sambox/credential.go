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
	"fmt"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/google/sam/internal/identity"
)

// Without this, a bundle is self-asserting: whoever can write the file decides
// which agent the sandbox is, and the identity the whole mesh then reasons
// about rests on a YAML field. Verification makes the bundle a claim that has
// to be backed by a credential the platform issued to that workload — a
// projected Kubernetes service-account token today.
//
// The issuer is deliberately not read from the bundle. The bundle travels with
// the agent and is therefore exactly as trustworthy as the agent; an issuer
// named there could be one the attacker controls, and self-signed credentials
// would verify perfectly. It comes from the operator instead, on the command
// line beside the socket paths.

// WorkloadVerifier checks the credential a platform issued to a sandbox.
type WorkloadVerifier struct {
	providers map[string]*oidc.Provider
	audiences []string
}

// NewWorkloadVerifier resolves the issuer, which requires reaching its
// discovery endpoint, so a misconfigured issuer fails at startup rather than
// on the first agent.
func NewWorkloadVerifier(ctx context.Context, issuer, audience string) (*WorkloadVerifier, error) {
	if issuer == "" || audience == "" {
		return nil, fmt.Errorf("both a credential issuer and an audience are required")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("resolving the credential issuer %s: %w", issuer, err)
	}
	return &WorkloadVerifier{
		providers: map[string]*oidc.Provider{issuer: provider},
		audiences: []string{audience},
	}, nil
}

// Verify reports whether the bundle's credential attests the identity the
// bundle claims.
//
// The check that matters is the last one: the credential's subject must be the
// external identity the bundle declares. Verifying the signature alone would
// only prove the sandbox holds *a* valid credential, which every sandbox on the
// platform does, and any of them could then claim to be any other.
func (v *WorkloadVerifier) Verify(ctx context.Context, bundle *AgentBundle) error {
	if bundle.Agent.Credential == "" {
		return fmt.Errorf("agent %s declares no credential, and this gateway verifies them", bundle.Agent.ID)
	}
	if bundle.Agent.ExternalID == "" {
		return fmt.Errorf("agent %s declares no external_id, so there is nothing for its credential to attest", bundle.Agent.ID)
	}

	raw, err := os.ReadFile(bundle.Agent.Credential)
	if err != nil {
		return fmt.Errorf("reading the credential for agent %s: %w", bundle.Agent.ID, err)
	}

	claims, _, err := identity.VerifyJWT(ctx, strings.TrimSpace(string(raw)), v.audiences, v.providers)
	if err != nil {
		return fmt.Errorf("verifying the credential for agent %s: %w", bundle.Agent.ID, err)
	}

	subject, _ := claims["sub"].(string)
	if subject == "" {
		return fmt.Errorf("the credential for agent %s attests no subject", bundle.Agent.ID)
	}
	if subject != bundle.Agent.ExternalID {
		return fmt.Errorf("agent %s claims to be %q, but its credential attests %q",
			bundle.Agent.ID, bundle.Agent.ExternalID, subject)
	}
	return nil
}
