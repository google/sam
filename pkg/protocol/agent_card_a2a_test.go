package protocol_test

import (
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"sam/pkg/protocol"
)

func TestToA2ACard(t *testing.T) {
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
		[]string{"inference", "search"},
		[]protocol.MCPResource{{Name: "mcp", Kind: "tool"}},
		priv,
	)
	if err != nil {
		t.Fatalf("NewAgentCard() error = %v", err)
	}

	a2aCard, err := card.ToA2ACard("https://example.com/a2a")
	if err != nil {
		t.Fatalf("ToA2ACard() error = %v", err)
	}
	if a2aCard.Version != card.Version {
		t.Fatalf("a2a version = %q, want %q", a2aCard.Version, card.Version)
	}
	if len(a2aCard.Skills) != 2 {
		t.Fatalf("len(skills) = %d, want 2", len(a2aCard.Skills))
	}
	if len(a2aCard.SupportedInterfaces) != 1 {
		t.Fatalf("len(supportedInterfaces) = %d, want 1", len(a2aCard.SupportedInterfaces))
	}
}

func TestAgentCardFromA2A(t *testing.T) {
	a2aCard := &a2a.AgentCard{
		SupportedInterfaces: []*a2a.AgentInterface{a2a.NewAgentInterface("https://example.com/a2a", a2a.TransportProtocolJSONRPC)},
		Capabilities:        a2a.AgentCapabilities{Streaming: true},
		DefaultInputModes:   []string{"application/json"},
		DefaultOutputModes:  []string{"application/json"},
		Description:         "test",
		Name:                "test-agent",
		Skills: []a2a.AgentSkill{
			{ID: "inference", Name: "Inference", Description: "run inference", Tags: []string{"sam"}},
		},
		Version: "a2a.v1",
	}

	card, err := protocol.AgentCardFromA2A("12D3KooWQK6Jk5hY5YAL3mVyYBVN1w8w5kZdeMNF8f9mJ5JPgX5R", a2aCard, nil)
	if err != nil {
		t.Fatalf("AgentCardFromA2A() error = %v", err)
	}
	capabilities := card.CapabilityNames()
	if len(capabilities) != 1 || capabilities[0] != "inference" {
		t.Fatalf("capabilities = %#v, want [inference]", capabilities)
	}
	card.IssuedAt = time.Now().UTC()
	if card.Algorithm != protocol.AgentCardSignAlgo {
		t.Fatalf("algorithm = %q, want %q", card.Algorithm, protocol.AgentCardSignAlgo)
	}
}
