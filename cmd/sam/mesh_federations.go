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
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	internaldb "sam/internal/db"
)

// newMeshFederationsCmd builds the "sam mesh federations" sub-group.
func newMeshFederationsCmd(_ *runConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "federations",
		Short: "Manage federation storage contexts",
		Long: `Manage isolated storage contexts (federations).

Each federation stores its own peer vouches, reputation scores, and discovery
cache in a separate database at ~/.config/sam/federations/<name>.db.

The master identity key stays at ~/.config/sam/state.db and is never affected
by federation operations.`,
	}
	cmd.AddCommand(newMeshFederationsListCmd())
	cmd.AddCommand(newMeshFederationsDropCmd())
	return cmd
}

// newMeshFederationsListCmd builds "sam mesh federations list".
func newMeshFederationsListCmd() *cobra.Command {
	var outputFmt string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all federation databases on disk",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMeshFederationsList(outputFmt)
		},
	}
	cmd.Flags().StringVarP(&outputFmt, "output", "o", "table", "output format: table|json")
	return cmd
}

func runMeshFederationsList(format string) error {
	mgr, err := internaldb.NewManager()
	if err != nil {
		return fmt.Errorf("creating federation manager: %w", err)
	}
	defer func() { _ = mgr.Close() }()

	names, err := mgr.ListFederations()
	if err != nil {
		return fmt.Errorf("listing federations: %w", err)
	}

	if len(names) == 0 {
		_, _ = fmt.Fprintln(os.Stdout, "No federation databases found.")
		_, _ = fmt.Fprintf(os.Stdout, "Use --federation <name> with any command to create one.\n")
		return nil
	}

	switch format {
	case "json":
		type entry struct {
			Name string `json:"name"`
			Path string `json:"path"`
		}
		dir := mgr.BaseDir()
		out := make([]entry, len(names))
		for i, n := range names {
			out[i] = entry{Name: n, Path: dir + "/" + n + ".db"}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	default:
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "NAME\tPATH")
		for _, n := range names {
			_, _ = fmt.Fprintf(w, "%s\t%s/%s.db\n", n, mgr.BaseDir(), n)
		}
		return w.Flush()
	}
}

// newMeshFederationsDropCmd builds "sam mesh federations drop <name>".
func newMeshFederationsDropCmd() *cobra.Command {
	var confirm bool
	cmd := &cobra.Command{
		Use:   "drop <name>",
		Short: "Delete a federation database and all its data",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMeshFederationsDrop(args[0], confirm)
		},
	}
	cmd.Flags().BoolVar(&confirm, "confirm", false, "required: confirm destructive deletion")
	return cmd
}

func runMeshFederationsDrop(name string, confirmed bool) error {
	if !confirmed {
		return fmt.Errorf("destructive operation: re-run with --confirm to delete federation %q", name)
	}

	mgr, err := internaldb.NewManager()
	if err != nil {
		return fmt.Errorf("creating federation manager: %w", err)
	}
	defer func() { _ = mgr.Close() }()

	if err := mgr.DropFederation(name); err != nil {
		return fmt.Errorf("dropping federation %q: %w", name, err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "Federation %q dropped.\n", name)
	return nil
}
