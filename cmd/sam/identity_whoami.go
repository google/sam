package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"sam/pkg/identity"
)

func newIdentityWhoamiCmd(_ *runConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the currently stored identity and Hub credentials",
		Long: `Print the Hub-issued identity stored in ~/.config/sam/state.db.

Displays the bound PeerID, OIDC claims, and credential expiry. If no login
has been performed, prints a helpful message.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runIdentityWhoami()
		},
	}
}

func runIdentityWhoami() error {
	store, err := identity.DefaultCredentialStore()
	if err != nil {
		return fmt.Errorf("opening credential store: %w", err)
	}
	defer func() { _ = store.Close() }()

	creds, err := store.Load()
	if err != nil {
		return fmt.Errorf("loading credentials: %w", err)
	}
	if creds == nil {
		_, _ = fmt.Fprintln(os.Stdout, "Not logged in. Run `sam identity login --hub <url>` to authenticate.")
		return nil
	}

	_, _ = fmt.Fprintf(os.Stdout, "Hub    : %s\n", creds.HubURL)
	if creds.PeerID != "" {
		_, _ = fmt.Fprintf(os.Stdout, "PeerID : %s\n", creds.PeerID)
	}

	if !creds.TokenExpiry.IsZero() {
		if time.Now().After(creds.TokenExpiry) {
			_, _ = fmt.Fprintf(os.Stdout, "Token  : EXPIRED (was %s)\n", creds.TokenExpiry.Format(time.RFC3339))
		} else {
			_, _ = fmt.Fprintf(os.Stdout, "Token  : valid until %s\n", creds.TokenExpiry.Format(time.RFC3339))
		}
	}

	if v := creds.Vouch; v != nil {
		_, _ = fmt.Fprintf(os.Stdout, "PeerID : %s\n", v.PeerID)
		if v.Subject != "" {
			_, _ = fmt.Fprintf(os.Stdout, "Subject: %s\n", v.Subject)
		}
		if email := v.Email(); email != "" {
			_, _ = fmt.Fprintf(os.Stdout, "Email  : %s\n", email)
		}
		if name := v.Name(); name != "" {
			_, _ = fmt.Fprintf(os.Stdout, "Name   : %s\n", name)
		}
		if org := v.Org(); org != "" {
			_, _ = fmt.Fprintf(os.Stdout, "Org    : %s\n", org)
		}
		_, _ = fmt.Fprintf(os.Stdout, "Issuer : %s\n", v.Issuer)
		if v.IsExpired() {
			_, _ = fmt.Fprintf(os.Stdout, "Vouch  : EXPIRED (was %s)\n", v.Expiry.Format(time.RFC3339))
		} else {
			_, _ = fmt.Fprintf(os.Stdout, "Vouch  : valid until %s\n", v.Expiry.Format(time.RFC3339))
		}
	} else {
		_, _ = fmt.Fprintln(os.Stdout, "Vouch  : none (Hub does not issue vouches, or run login again)")
	}
	return nil
}
