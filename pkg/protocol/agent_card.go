package protocol

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"sam/pkg/identity"
)

const (
	AgentCardVersion      = "a2a.v1"
	AgentCardSignAlgo     = "libp2p-ed25519"
	AgentDHTNamespaceBase = "/sam/v1/agents/"
)

// MCPResource describes an MCP-compatible tool or data source advertised by an agent.
type MCPResource struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Endpoint    string `json:"endpoint,omitempty"`
	Description string `json:"description,omitempty"`
}

// AgentCard is the signed capability document advertised in the SAM mesh.
//
// The signature covers all fields except Signature and Vouch.
// Vouch is attached after signing and allows peers to verify the operator's
// identity as asserted by a trusted Hub.
type AgentCard struct {
	a2a.AgentCard
	PeerID    string        `json:"peer_id"`
	Resources []MCPResource `json:"resources"`
	IssuedAt  time.Time     `json:"issued_at"`
	Algorithm string        `json:"alg"`
	Signature string        `json:"signature"`
	// Vouch is the optional Hub-signed identity credential bound to this PeerID.
	// It is not covered by the AgentCard signature; its own Hub signature provides
	// the authenticity guarantee.
	Vouch *identity.Vouch `json:"vouch,omitempty"`
}

type agentCardPayload struct {
	AgentCard a2a.AgentCard `json:"agent_card"`
	PeerID    string        `json:"peer_id"`
	Resources []MCPResource `json:"resources"`
	IssuedAt  time.Time     `json:"issued_at"`
	Algorithm string        `json:"alg"`
}

// NewAgentCard builds and signs an AgentCard for DHT advertisement.
func NewAgentCard(peerID peer.ID, capabilities []string, resources []MCPResource, privateKey crypto.PrivKey) (*AgentCard, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	if peerID == "" {
		return nil, fmt.Errorf("peer ID is required")
	}
	normalizedCaps := normalizeCapabilities(capabilities)
	if len(normalizedCaps) == 0 {
		return nil, fmt.Errorf("at least one capability is required")
	}
	skills := make([]a2a.AgentSkill, 0, len(normalizedCaps))
	for _, capability := range normalizedCaps {
		skills = append(skills, a2a.AgentSkill{
			ID:          capability,
			Name:        capability,
			Description: "SAM capability " + capability,
			Tags:        []string{"sam"},
		})
	}

	card := &AgentCard{
		AgentCard: a2a.AgentCard{
			Capabilities: a2a.AgentCapabilities{
				Streaming: true,
			},
			DefaultInputModes:  []string{"application/json"},
			DefaultOutputModes: []string{"application/json"},
			Description:        "SAM agent " + peerID.String(),
			Name:               "sam-agent-" + peerID.String(),
			Skills:             skills,
			Version:            AgentCardVersion,
		},
		PeerID:    peerID.String(),
		Resources: normalizeResources(resources),
		IssuedAt:  time.Now().UTC(),
		Algorithm: AgentCardSignAlgo,
	}

	if err := SignAgentCard(card, privateKey); err != nil {
		return nil, err
	}

	return card, nil
}

// SignAgentCard signs the card payload using the node private key.
func SignAgentCard(card *AgentCard, privateKey crypto.PrivKey) error {
	if card == nil {
		return fmt.Errorf("agent card is nil")
	}
	if privateKey == nil {
		return fmt.Errorf("private key is required")
	}
	if err := card.validateBase(); err != nil {
		return err
	}

	payload, err := card.signingPayload()
	if err != nil {
		return fmt.Errorf("encoding card payload: %w", err)
	}

	sig, err := privateKey.Sign(payload)
	if err != nil {
		return fmt.Errorf("signing card payload: %w", err)
	}
	card.Signature = base64.RawURLEncoding.EncodeToString(sig)
	return nil
}

// VerifyAgentCard verifies card integrity and signature against the embedded PeerID.
func VerifyAgentCard(card *AgentCard) error {
	if card == nil {
		return fmt.Errorf("agent card is nil")
	}
	if err := card.validateBase(); err != nil {
		return err
	}
	if strings.TrimSpace(card.Signature) == "" {
		return fmt.Errorf("card signature is required")
	}

	pid, err := peer.Decode(card.PeerID)
	if err != nil {
		return fmt.Errorf("invalid peer ID %q: %w", card.PeerID, err)
	}
	pub, err := pid.ExtractPublicKey()
	if err != nil {
		return fmt.Errorf("extracting public key from peer ID: %w", err)
	}

	payload, err := card.signingPayload()
	if err != nil {
		return fmt.Errorf("encoding card payload: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(card.Signature)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	ok, err := pub.Verify(payload, sig)
	if err != nil {
		return fmt.Errorf("verifying signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("agent card signature invalid")
	}
	return nil
}

// Sign signs the current card payload using the provided private key.
func (c *AgentCard) Sign(privateKey crypto.PrivKey) error {
	return SignAgentCard(c, privateKey)
}

// Verify checks card integrity and signature against the embedded PeerID.
func (c *AgentCard) Verify() error {
	return VerifyAgentCard(c)
}

// AttachVouch sets the Vouch on an AgentCard. The Vouch is not covered by the
// AgentCard signature; its own Hub signature guarantees authenticity.
// Passing nil clears any previously attached Vouch.
func (c *AgentCard) AttachVouch(v *identity.Vouch) {
	c.Vouch = v
}

func (c *AgentCard) validateBase() error {
	if strings.TrimSpace(c.Version) == "" {
		return fmt.Errorf("card version is required")
	}
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("card name is required")
	}
	if strings.TrimSpace(c.PeerID) == "" {
		return fmt.Errorf("card peer ID is required")
	}
	if _, err := peer.Decode(c.PeerID); err != nil {
		return fmt.Errorf("invalid peer ID %q: %w", c.PeerID, err)
	}
	if len(c.Skills) == 0 {
		return fmt.Errorf("at least one capability is required")
	}
	if c.IssuedAt.IsZero() {
		return fmt.Errorf("card issued_at is required")
	}
	if strings.TrimSpace(c.Algorithm) == "" {
		return fmt.Errorf("signature algorithm is required")
	}
	return nil
}

func (c *AgentCard) signingPayload() ([]byte, error) {
	p := agentCardPayload{
		AgentCard: normalizeA2ACard(c.AgentCard),
		PeerID:    c.PeerID,
		Resources: normalizeResources(c.Resources),
		IssuedAt:  c.IssuedAt.UTC(),
		Algorithm: c.Algorithm,
	}
	return json.Marshal(p)
}

// CapabilityNames returns normalized capability identifiers derived from A2A skills.
func (c *AgentCard) CapabilityNames() []string {
	if c == nil {
		return nil
	}
	names := make([]string, 0, len(c.Skills))
	for _, skill := range c.Skills {
		name := strings.TrimSpace(skill.ID)
		if name == "" {
			name = strings.TrimSpace(skill.Name)
		}
		if name != "" {
			names = append(names, name)
		}
	}
	return normalizeCapabilities(names)
}

func normalizeCapabilities(capabilities []string) []string {
	seen := make(map[string]struct{}, len(capabilities))
	out := make([]string, 0, len(capabilities))
	for _, c := range capabilities {
		n := strings.ToLower(strings.TrimSpace(c))
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func normalizeResources(resources []MCPResource) []MCPResource {
	out := make([]MCPResource, 0, len(resources))
	for _, r := range resources {
		r.Name = strings.TrimSpace(r.Name)
		r.Kind = strings.TrimSpace(r.Kind)
		r.Endpoint = strings.TrimSpace(r.Endpoint)
		r.Description = strings.TrimSpace(r.Description)
		if r.Name == "" {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func normalizeA2ACard(card a2a.AgentCard) a2a.AgentCard {
	card.Skills = normalizeSkills(card.Skills)
	card.SupportedInterfaces = normalizeInterfaces(card.SupportedInterfaces)
	card.Signatures = nil
	return card
}

func normalizeSkills(skills []a2a.AgentSkill) []a2a.AgentSkill {
	cloned := append([]a2a.AgentSkill(nil), skills...)
	for index := range cloned {
		cloned[index].ID = strings.TrimSpace(cloned[index].ID)
		cloned[index].Name = strings.TrimSpace(cloned[index].Name)
		cloned[index].Description = strings.TrimSpace(cloned[index].Description)
		sort.Strings(cloned[index].Tags)
		sort.Strings(cloned[index].Examples)
		sort.Strings(cloned[index].InputModes)
		sort.Strings(cloned[index].OutputModes)
	}
	sort.Slice(cloned, func(i, j int) bool {
		return cmp.Or(
			strings.Compare(cloned[i].ID, cloned[j].ID),
			strings.Compare(cloned[i].Name, cloned[j].Name),
		) < 0
	})
	return cloned
}

func normalizeInterfaces(in []*a2a.AgentInterface) []*a2a.AgentInterface {
	cloned := make([]*a2a.AgentInterface, 0, len(in))
	for _, item := range in {
		if item == nil {
			continue
		}
		copyItem := *item
		copyItem.URL = strings.TrimSpace(copyItem.URL)
		copyItem.Tenant = strings.TrimSpace(copyItem.Tenant)
		cloned = append(cloned, &copyItem)
	}
	sort.Slice(cloned, func(i, j int) bool {
		return cmp.Or(
			strings.Compare(cloned[i].URL, cloned[j].URL),
			strings.Compare(string(cloned[i].ProtocolBinding), string(cloned[j].ProtocolBinding)),
		) < 0
	})
	return cloned
}
