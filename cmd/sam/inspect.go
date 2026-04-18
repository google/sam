package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"sam/pkg/economy"
	"sam/pkg/protocol"
)

// newInspectCmd creates the "sam inspect" command for decoding SAM artifacts.
func newInspectCmd(cfg *runConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Decode and explain SAM artifacts (biscuit, card)",
		Long: `Inspect and decode SAM artifacts for auditing and transparency.

Usage:
  sam inspect biscuit <token>      Decode a Biscuit token and explain caveats
  sam inspect card <peer-id|json>  Decode an Agent Card and display metadata`,
	}

	cmd.AddCommand(newInspectBiscuitCmd(cfg))
	cmd.AddCommand(newInspectCardCmd(cfg))
	return cmd
}

// newInspectBiscuitCmd decodes a Biscuit token and displays its caveats.
func newInspectBiscuitCmd(cfg *runConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "biscuit <token>",
		Short: "Decode and explain a Biscuit token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInspectBiscuit(cfg, strings.TrimSpace(args[0]))
		},
	}
}

func runInspectBiscuit(cfg *runConfig, token string) error {
	if token == "" {
		return fmt.Errorf("token is required")
	}

	// Parse the token using BiscuitSkillGate logic
	parser := economy.SimpleBiscuitParser{}
	parsed, err := parser.Parse(context.Background(), token)
	if err != nil {
		return fmt.Errorf("parsing biscuit: %w", err)
	}

	// Build human-readable explanation
	explanation := buildBiscuitExplanation(parsed)

	// Output format
	if cfg.outputFormat == "json" {
		result := map[string]interface{}{
			"subject":        parsed.Subject,
			"allowed_skills": parsed.AllowedSkills,
			"explanation":    explanation,
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Subject: %s\n", parsed.Subject)
		if len(parsed.AllowedSkills) > 0 {
			fmt.Printf("Allowed Skills: %s\n", strings.Join(parsed.AllowedSkills, ", "))
		} else {
			fmt.Println("Allowed Skills: (unrestricted)")
		}
		fmt.Printf("\nHuman Language Summary:\n%s\n", explanation)
	}
	return nil
}

// buildBiscuitExplanation generates a human-readable explanation of a Biscuit.
func buildBiscuitExplanation(parsed *economy.ParsedBiscuit) string {
	subject := parsed.Subject
	if len(parsed.AllowedSkills) == 0 {
		return fmt.Sprintf("This token issued to '%s' grants unrestricted access to all skills.", subject)
	}

	if len(parsed.AllowedSkills) == 1 {
		return fmt.Sprintf("This token issued to '%s' allows the '%s' skill.", subject, parsed.AllowedSkills[0])
	}

	skills := strings.Join(parsed.AllowedSkills, "', '")
	return fmt.Sprintf("This token issued to '%s' allows the following skills: '%s'.", subject, skills)
}

// newInspectCardCmd decodes an Agent Card from JSON or peer ID.
func newInspectCardCmd(cfg *runConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "card <peer-id|json>",
		Short: "Decode and display an Agent Card",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInspectCard(cfg, strings.TrimSpace(args[0]))
		},
	}
}

func runInspectCard(cfg *runConfig, input string) error {
	if input == "" {
		return fmt.Errorf("peer-id or JSON is required")
	}

	// Try to parse as JSON first
	var card protocol.AgentCard
	if err := json.Unmarshal([]byte(input), &card); err != nil {
		// If JSON parsing fails, return helpful error message
		return fmt.Errorf("input must be valid JSON: %w", err)
	}

	// Output format
	if cfg.outputFormat == "json" {
		data, _ := json.MarshalIndent(card, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Peer ID:     %s\n", card.PeerID)
		fmt.Printf("Name:        %s\n", card.AgentCard.Name)
		fmt.Printf("Description: %s\n", card.AgentCard.Description)
		fmt.Printf("Version:     %s\n", card.Version)
		fmt.Printf("Algorithm:   %s\n", card.Algorithm)
		fmt.Printf("Issued At:   %s\n", card.IssuedAt.Format("2006-01-02T15:04:05Z07:00"))

		if len(card.AgentCard.Skills) > 0 {
			fmt.Println("\nSkills:")
			for _, skill := range card.AgentCard.Skills {
				fmt.Printf("  - %s: %s\n", skill.ID, skill.Description)
			}
		}

		if len(card.Resources) > 0 {
			fmt.Println("\nResources:")
			for _, res := range card.Resources {
				fmt.Printf("  - %s (%s): %s\n", res.Name, res.Kind, res.Endpoint)
			}
		}

		if card.Vouch != nil {
			fmt.Println("\nIdentity Vouch:")
			fmt.Printf("  Issuer:    %s\n", card.Vouch.Issuer)
			fmt.Printf("  Subject:   %s\n", card.Vouch.Subject)
			if email, ok := card.Vouch.Claims["email"]; ok {
				fmt.Printf("  Email:     %s\n", email)
			}
			if name, ok := card.Vouch.Claims["name"]; ok {
				fmt.Printf("  Name:      %s\n", name)
			}
		}

		fmt.Printf("\nSignature:   %s\n", truncateString(card.Signature, 20))
	}
	return nil
}

// truncateString limits a string to n characters and adds ellipsis.
func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
