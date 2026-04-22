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

package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"sam/pkg/identity"
)

const (
	defaultClientID = "sam-cli"
)

func newIdentityLoginCmd(cfg *runConfig) *cobra.Command {
	var clientID string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with a Hub using the OAuth2 Device Authorization Grant",
		Long: `Authenticate with a SAM Hub using the OAuth2 Device Authorization Grant.

The CLI prints a short URL and a user code. Open the URL in any browser,
enter the code, and complete the sign-in. The CLI polls until you finish,
then saves credentials to ~/.config/sam/state.db.

The Hub URL defaults to --hub (global flag) or the SAM_HUB environment
variable. Any Hub that implements OIDC Device Flow is supported:

	sam-agent identity login --hub https://hub.internal.bank
	sam-agent identity login --hub https://hub.example.com --client-id my-app`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runIdentityLogin(cmd.Context(), cfg, clientID)
		},
	}
	cmd.Flags().StringVar(&clientID, "client-id", defaultClientID,
		"OAuth2 client ID registered with the Hub")
	return cmd
}

func runIdentityLogin(parent context.Context, cfg *runConfig, clientID string) error {
	hubURL := resolveHubURL(cfg)
	if hubURL == "" {
		return fmt.Errorf("hub URL is required: set --hub, SAM_HUB env var, or use a stored identity")
	}

	fmt.Fprintf(os.Stderr, "Fetching Hub discovery document from %s …\n", hubURL)
	disc, err := identity.FetchHubDiscovery(parent, hubURL)
	if err != nil {
		return fmt.Errorf("hub discovery: %w (make sure the Hub is reachable and implements OIDC discovery)", err)
	}

	flowCfg := identity.DeviceFlowConfig{ClientID: clientID}
	auth, err := identity.StartDeviceFlow(parent, disc.DeviceAuthEndpoint, flowCfg)
	if err != nil {
		return fmt.Errorf("starting device flow: %w", err)
	}

	// Present the code to the user.
	verifyURL := auth.VerificationURIComplete
	if verifyURL == "" {
		verifyURL = auth.VerificationURI
	}
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  Open this URL in your browser:\n\n")
	fmt.Fprintf(os.Stderr, "    %s\n\n", verifyURL)
	if auth.VerificationURIComplete == "" {
		fmt.Fprintf(os.Stderr, "  And enter code: %s\n\n", auth.UserCode)
	}
	fmt.Fprintf(os.Stderr, "Waiting for authorization (expires in %ds) …\n", auth.ExpiresIn)

	result, err := identity.PollDeviceToken(parent, disc.TokenEndpoint, auth, flowCfg)
	if err != nil {
		return fmt.Errorf("device flow: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Authorization successful. Issuing identity passport …\n")

	// Build the node to obtain our stable PeerID.
	node, err := buildNode(cfg)
	if err != nil {
		return err
	}
	if err := node.Start(parent); err != nil {
		return fmt.Errorf("starting node: %w", err)
	}
	defer func() { _ = node.Stop(context.Background()) }()
	peerID := node.PeerID().String()

	issueReq := identity.PassportIssueRequest{
		PeerID:       peerID,
		FederationID: defaultFederationID,
		Subject:      peerID,
		Claims:       map[string]string{"hub": hubURL},
	}
	passportEndpoint := strings.TrimRight(hubURL, "/") + "/issue-passport"
	passportBiscuit, err := identity.FetchPassportBiscuit(parent, passportEndpoint, result.AccessToken, issueReq)
	if err != nil {
		return fmt.Errorf("fetching hub-issued passport biscuit: %w", err)
	}

	store, err := identity.DefaultCredentialStore()
	if err != nil {
		return fmt.Errorf("opening credential store: %w", err)
	}
	defer func() { _ = store.Close() }()

	creds := &identity.StoredCredentials{
		PeerID:          peerID,
		HubURL:          hubURL,
		AccessToken:     result.AccessToken,
		RefreshToken:    result.RefreshToken,
		TokenExpiry:     result.TokenExpiry,
		PassportBiscuit: passportBiscuit,
	}
	if err := store.Save(creds); err != nil {
		return fmt.Errorf("saving credentials: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nLogged in as peer %s\n", peerID)
	if claims, pErr := identity.ValidatePassportBiscuit(parent, passportBiscuit, peerID, defaultFederationID); pErr == nil {
		fmt.Fprintf(os.Stderr, "Subject: %s\n", claims.Subject)
		fmt.Fprintf(os.Stderr, "Federation: %s\n", claims.FederationID)
	}
	fmt.Fprintf(os.Stderr, "Credentials saved to %s\n", store.Path())
	return nil
}

// resolveHubURL returns the hub URL from the flag, then the environment.
func resolveHubURL(cfg *runConfig) string {
	if cfg.hub != "" {
		return cfg.hub
	}
	return os.Getenv("SAM_HUB")
}
