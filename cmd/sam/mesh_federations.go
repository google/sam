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
	defer mgr.Close()

	names, err := mgr.ListFederations()
	if err != nil {
		return fmt.Errorf("listing federations: %w", err)
	}

	if len(names) == 0 {
		fmt.Fprintln(os.Stdout, "No federation databases found.")
		fmt.Fprintf(os.Stdout, "Use --federation <name> with any command to create one.\n")
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
		fmt.Fprintln(w, "NAME\tPATH")
		for _, n := range names {
			fmt.Fprintf(w, "%s\t%s/%s.db\n", n, mgr.BaseDir(), n)
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
	defer mgr.Close()

	if err := mgr.DropFederation(name); err != nil {
		return fmt.Errorf("dropping federation %q: %w", name, err)
	}
	fmt.Fprintf(os.Stdout, "Federation %q dropped.\n", name)
	return nil
}
