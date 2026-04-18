package main

import "github.com/spf13/cobra"

// newIdentityCmd creates the "sam identity" group command.
func newIdentityCmd(cfg *runConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Manage SAM node identity and Hub credentials",
	}
	cmd.AddCommand(newIdentityLoginCmd(cfg))
	cmd.AddCommand(newIdentityWhoamiCmd(cfg))
	return cmd
}
