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
