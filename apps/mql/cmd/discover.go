// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.mondoo.com/mql/cli/inventoryloader"
	"go.mondoo.com/mql/discovery"
	"go.mondoo.com/mql/discovery/export"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func init() {
	rootCmd.AddCommand(DiscoverCmd)

	_ = DiscoverCmd.Flags().String("inventory-file", "", "Set the path to the inventory file")
	_ = DiscoverCmd.Flags().StringP("output-full", "o", "", "Write every discovered asset to this path. When empty, only the per-platform count summary is printed.")
	_ = DiscoverCmd.Flags().StringP("output-format", "f", string(export.FormatJSON), "Format for --output-full: json (default), jsonl, or yaml.")
}

var DiscoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover assets",
	Long:  `Discover assets defined by an inventory file's discovery targets/filters or via CLI parameters. Prints a per-platform asset count to stdout. Pass --output-full <path> to additionally write every discovered asset to a file; pick the file format with --output-format json|jsonl|yaml (default json). No queries are executed.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		_ = viper.BindPFlag("inventory-file", cmd.Flags().Lookup("inventory-file"))
	},
	// initialized empty so cobra treats this as a runnable command in --help
	Run: func(cmd *cobra.Command, args []string) {},
}

var DiscoverCmdRun = func(cmd *cobra.Command, runtime *providers.Runtime, cliRes *plugin.ParseCLIRes) {
	ctx := context.Background()

	outPath, _ := cmd.Flags().GetString("output-full")
	formatStr, _ := cmd.Flags().GetString("output-format")
	format, err := export.ParseFormat(formatStr)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid --output-format")
	}

	in, err := inventoryloader.ParseOrUse(cliRes.Asset, viper.GetBool("insecure"), nil)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to resolve inventory")
	}

	// Enable staged discovery so providers can split discovery into phases —
	// same posture mql run uses, keeps memory bounded for large inventories.
	if in.Spec != nil {
		for _, asset := range in.Spec.Assets {
			for _, conn := range asset.Connections {
				if conn.Options == nil {
					conn.Options = map[string]string{}
				}
				conn.Options[plugin.OptionStagedDiscovery] = ""
			}
		}
	}

	explorer, err := discovery.NewAssetExplorer(ctx, discovery.AssetExplorerConfig{
		Inventory: in,
		Recording: runtime.Recording(),
	})
	if err != nil {
		log.Fatal().Err(err).Msg("could not start discovery")
	}
	defer explorer.Shutdown()

	// Recursively connect all first-level discovered children so deeper
	// children are surfaced too. Without this, mql discover would only emit
	// the inventory's roots plus their immediate children.
	connectAll(explorer, explorer.Discovered())

	assets := export.CollectExploredAssets(explorer)
	printPlatformSummary(assets)

	if outPath == "" {
		return
	}

	if len(assets) == 0 {
		log.Info().Msg("no assets were discovered")
		return
	}

	f, err := os.Create(outPath)
	if err != nil {
		log.Fatal().Err(err).Str("path", outPath).Msg("failed to create output file")
	}

	if err := export.WriteAssets(f, assets, format); err != nil {
		_ = f.Close()
		log.Fatal().Err(err).Msg("failed to write discovered assets")
	}
	if err := f.Close(); err != nil {
		log.Fatal().Err(err).Str("path", outPath).Msg("failed to close output file")
	}
	log.Info().Str("path", outPath).Str("format", string(format)).Msg("discovered assets written")
}

// printPlatformSummary writes a per-platform asset count to stdout, sorted
// alphabetically by platform name. Always runs, regardless of --output-full.
func printPlatformSummary(assets []*inventory.Asset) {
	counts := map[string]int{}
	for _, a := range assets {
		name := a.GetPlatform().GetName()
		if name == "" {
			name = "<unknown>"
		}
		counts[name]++
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Println("Discovered assets:")
	for _, name := range names {
		fmt.Printf("%s: %d\n", name, counts[name])
	}
}
