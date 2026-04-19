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

package protocol_test

import (
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"sam/pkg/protocol"
)

func TestAgentCardSignVerify(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey() error = %v", err)
	}

	card, err := protocol.NewAgentCard(
		pid,
		[]string{"Inference", "search", "search"},
		[]protocol.MCPResource{{Name: "local-mcp", Kind: "tool", Endpoint: "unix:///tmp/mcp.sock"}},
		priv,
	)
	if err != nil {
		t.Fatalf("NewAgentCard() error = %v", err)
	}

	if err := protocol.VerifyAgentCard(card); err != nil {
		t.Fatalf("VerifyAgentCard() error = %v", err)
	}

	capabilities := card.CapabilityNames()
	if len(capabilities) != 2 || capabilities[0] != "inference" || capabilities[1] != "search" {
		t.Fatalf("normalized capabilities = %#v, want [inference search]", capabilities)
	}
}

func TestAgentCardVerifyRejectsTamper(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey() error = %v", err)
	}

	card, err := protocol.NewAgentCard(
		pid,
		[]string{"inference"},
		nil,
		priv,
	)
	if err != nil {
		t.Fatalf("NewAgentCard() error = %v", err)
	}

	card.Skills = append(card.Skills, card.Skills[0])
	card.Skills[1].ID = "search"
	card.Skills[1].Name = "search"
	if err := protocol.VerifyAgentCard(card); err == nil {
		t.Fatal("VerifyAgentCard() should fail for tampered card")
	}
}

func TestAgentCardVerifyRejectsMissingSignature(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey() error = %v", err)
	}

	card := &protocol.AgentCard{
		AgentCard: a2a.AgentCard{
			Name:    "sam-agent-" + pid.String(),
			Skills:  []a2a.AgentSkill{{ID: "inference", Name: "inference"}},
			Version: protocol.AgentCardVersion,
		},
		PeerID:    pid.String(),
		IssuedAt:  time.Now().UTC(),
		Algorithm: protocol.AgentCardSignAlgo,
	}

	if err := protocol.VerifyAgentCard(card); err == nil {
		t.Fatal("VerifyAgentCard() should fail without signature")
	}
}
