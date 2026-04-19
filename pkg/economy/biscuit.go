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
	"fmt"
	"strings"
)

// ErrSkillCaveatDenied is returned when the Biscuit token does not authorize
// the requested skill (allow_skill caveat mismatch).
var ErrSkillCaveatDenied = errors.New("biscuit skill caveat denied")

// ParsedBiscuit holds the claims extracted from a raw Biscuit token.
// In this simplified implementation the token itself encodes caveats as a
// structured string of the form:
//
//	<subject>;<allow_skill=skill1,skill2,...>
//
// A full implementation would parse a cryptographically-verified Biscuit using
// the biscuit-go library.  This interface keeps the contract stable for that
// future migration.
type ParsedBiscuit struct {
	Subject       string
	AllowedSkills []string // empty means "allow all"
}

// BiscuitParser extracts claims from a raw token string.
type BiscuitParser interface {
	Parse(ctx context.Context, token string) (*ParsedBiscuit, error)
}

// SimpleBiscuitParser parses the lightweight plain-text format used in the
// SAM reference implementation:
//
//	<subject>;<allow_skill=weather-bot,risk-audit>
//
// Tokens with no caveat section allow all skills.
type SimpleBiscuitParser struct{}

func (SimpleBiscuitParser) Parse(_ context.Context, token string) (*ParsedBiscuit, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}
	parts := strings.SplitN(token, ";", 2)
	p := &ParsedBiscuit{Subject: parts[0]}
	if len(parts) < 2 {
		return p, nil // no caveats → allow all
	}
	caveat := strings.TrimSpace(parts[1])
	const skillPrefix = "allow_skill="
	if strings.HasPrefix(caveat, skillPrefix) {
		raw := strings.TrimPrefix(caveat, skillPrefix)
		for _, s := range strings.Split(raw, ",") {
			if s = strings.TrimSpace(s); s != "" {
				p.AllowedSkills = append(p.AllowedSkills, s)
			}
		}
	}
	return p, nil
}

// BiscuitSkillGate is an A2A-layer guard that verifies the requested skill
// appears in the token's allow_skill caveat list before forwarding the stream.
//
// It is designed to be composed with A2AService via FederationGate or
// directly called from the A2A header validation path.
type BiscuitSkillGate struct {
	parser BiscuitParser
}

// NewBiscuitSkillGate creates a gate using the given parser.
// Pass nil to use SimpleBiscuitParser.
func NewBiscuitSkillGate(parser BiscuitParser) *BiscuitSkillGate {
	if parser == nil {
		parser = SimpleBiscuitParser{}
	}
	return &BiscuitSkillGate{parser: parser}
}

// CheckSkill returns nil if the token authorises the given skill, or a
// typed ErrSkillCaveatDenied error when the caveat is violated.
func (g *BiscuitSkillGate) CheckSkill(ctx context.Context, token, skill string) error {
	parsed, err := g.parser.Parse(ctx, token)
	if err != nil {
		return fmt.Errorf("parsing biscuit: %w", err)
	}
	// No caveats means unrestricted.
	if len(parsed.AllowedSkills) == 0 {
		return nil
	}
	for _, allowed := range parsed.AllowedSkills {
		if strings.EqualFold(allowed, skill) {
			return nil
		}
	}
	return fmt.Errorf("%w: token for %q does not allow skill %q (allowed: %s)",
		ErrSkillCaveatDenied, parsed.Subject, skill,
		strings.Join(parsed.AllowedSkills, ", "))
}
