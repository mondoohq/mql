// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"go.mondoo.com/mql/cli/inventoryvalidate"
	"go.mondoo.com/mql/cli/theme"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func init() {
	rootCmd.AddCommand(inventoryCmd)
	inventoryCmd.AddCommand(inventoryValidateCmd)
	inventoryValidateCmd.Flags().Bool("strict", false,
		"Treat warnings (unknown options, uninstalled connection types) as errors")
}

var inventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Work with inventory files",
	Long:  "Inspect and validate inventory files.",
}

var inventoryValidateCmd = &cobra.Command{
	Use:   "validate <file>",
	Short: "Validate an inventory file against installed provider schemas",
	Long: `Validate parses an inventory file and checks each asset connection against
the provider that handles it. Connection types that no installed provider
provides, and option keys that the provider's connectors do not declare, are
reported — these are typically typos that would otherwise be silently ignored
when the scan runs.

Option keys are matched against each provider's connector flag names, so the
set of valid options always reflects the providers you have installed.`,
	Example: `  mql inventory validate inventory.yml
  mql inventory validate inventory.yml --strict`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		strict, _ := cmd.Flags().GetBool("strict")
		path := args[0]

		inv, err := inventory.InventoryFromFile(path)
		if err != nil {
			return fmt.Errorf("failed to load inventory %q: %w", path, err)
		}

		all, err := providers.ListAll()
		if err != nil {
			return fmt.Errorf("failed to list installed providers: %w", err)
		}
		plugins := make([]*plugin.Provider, 0, len(all))
		for _, p := range all {
			if p != nil && p.Provider != nil {
				plugins = append(plugins, p.Provider)
			}
		}

		schema := inventoryvalidate.BuildSchema(plugins)
		findings := inventoryvalidate.Check(inv, schema, strict)

		errCount := 0
		for _, f := range findings {
			line := fmt.Sprintf("%s: %s (asset %s, connection %d)",
				f.Severity, f.Message, f.Asset, f.Connection)
			if f.Severity == inventoryvalidate.SeverityError {
				errCount++
				line = theme.DefaultTheme.Error(line)
			} else {
				line = theme.DefaultTheme.Secondary(line)
			}
			cmd.PrintErrln(line)
		}

		switch {
		case len(findings) == 0:
			cmd.Printf("inventory %q is valid\n", path)
			return nil
		case errCount > 0:
			return fmt.Errorf("inventory %q has %d error(s)", path, errCount)
		default:
			cmd.Printf("inventory %q passed with %d warning(s); use --strict to fail on warnings\n",
				path, len(findings))
			return nil
		}
	},
}
