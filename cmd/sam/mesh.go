package main

import "github.com/spf13/cobra"

// newMeshCmd creates the "sam mesh" group command and its subcommands.
func newMeshCmd(cfg *runConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mesh",
		Short: "Inspect and interact with the SAM agent mesh",
	}
	cmd.AddCommand(newMeshGetCmd(cfg))
	cmd.AddCommand(newMeshFederationsCmd(cfg))
	return cmd
}

// newMeshGetCmd creates the "sam mesh get" sub-group.
func newMeshGetCmd(cfg *runConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Retrieve resources from the mesh",
	}
	// -o / --output is a persistent flag so every "get" leaf inherits it.
	cmd.PersistentFlags().StringVarP(&cfg.outputFormat, "output", "o", "table",
		"output format: table|json")

	cmd.AddCommand(newMeshGetAgentsCmd(cfg))
	return cmd
}
