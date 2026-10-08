// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"context"
	"fmt"
	"os"
	"slices"

	"github.com/cockroachdb/errors"
	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/cli/components"
	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/cli/inventoryloader"
	"go.mondoo.com/mql/cli/shell"
	"go.mondoo.com/mql/cli/theme"
	"go.mondoo.com/mql/discovery"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
)

func init() {
	rootCmd.AddCommand(shellCmd)

	shellCmd.Flags().StringP("command", "c", "", "MQL query to execute in the shell")
	shellCmd.Flags().String("platform-id", "", "Select a specific target asset by providing its platform ID")
	shellCmd.Flags().String("inventory-file", "", "Set the path to an inventory file that defines exactly one asset to connect to, with its credentials")
	shellCmd.Flags().StringToString("annotations", nil, "Specify annotations for this run")
	_ = shellCmd.Flags().MarkHidden("annotations")
}

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Interactive query shell for MQL",
	Long:  `Allows the interactive exploration of MQL queries`,
	PreRun: func(cmd *cobra.Command, args []string) {
		_ = viper.BindPFlag("platform-id", cmd.Flags().Lookup("platform-id"))
		_ = viper.BindPFlag("annotations", cmd.Flags().Lookup("annotations"))
		_ = viper.BindPFlag("inventory-file", cmd.Flags().Lookup("inventory-file"))
	},
	// we have to initialize an empty run so it shows up as a runnable command in --help
	Run: func(cmd *cobra.Command, args []string) {},
}

var shellRun = func(cmd *cobra.Command, runtime *providers.Runtime, cliRes *plugin.ParseCLIRes) {
	shellConf := ParseShellConfig(cmd, cliRes)
	if err := StartShell(runtime, shellConf); err != nil {
		log.Fatal().Err(err).Msg("failed to run query")
	}
}

// ShellConfig is the shared configuration for running a shell given all
// commandline and config inputs.
// TODO: the config is a shared structure, which should be moved to proto
type ShellConfig struct {
	Command string
	Asset   *inventory.Asset
	// Inventory is the inventory the shell connects through. It carries the
	// credentials and vault configuration that Asset's secret references
	// resolve against. When nil, StartShell builds one from Asset alone.
	Inventory      *inventory.Inventory
	Features       mql.Features
	Strict         bool
	PlatformID     string
	WelcomeMessage string
	UpstreamConfig *upstream.UpstreamConfig
}

func ParseShellConfig(cmd *cobra.Command, cliRes *plugin.ParseCLIRes) *ShellConfig {
	conf, err := config.Read()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	config.DisplayUsedConfig()

	var upstreamConfig *upstream.UpstreamConfig
	serviceAccount := conf.GetServiceCredential()
	if serviceAccount != nil {
		upstreamConfig = &upstream.UpstreamConfig{
			// AssetMrn: not necessary right now, especially since incognito
			SpaceMrn:    conf.GetParentMrn(),
			ApiEndpoint: conf.UpstreamApiEndpoint(),
			ApiProxy:    conf.APIProxy,
			Incognito:   viper.GetBool("incognito"),
			Creds:       conf.GetServiceCredential(),
		}
	}

	annotations, _ := cmd.Flags().GetStringToString("annotations")
	cliRes.Asset.AddAnnotations(annotations)

	inv, err := ShellInventory(cliRes.Asset, viper.GetBool("insecure"), annotations)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load inventory")
	}

	shellConf := ShellConfig{
		Features:       config.Features,
		Strict:         config.Strict,
		PlatformID:     viper.GetString("platform-id"),
		Asset:          inv.Spec.Assets[0],
		Inventory:      inv,
		UpstreamConfig: upstreamConfig,
	}

	shellConf.Command, _ = cmd.Flags().GetString("command")
	return &shellConf
}

// ShellInventory loads the inventory a shell connects through: the one named
// by the "inventory-file" viper key when it is set, or else an inventory that
// holds just the CLI asset. It is the same loader `run` and `scan` use, so the
// asset's credentials resolve through the inventory's credentials section and
// vault instead of having to be passed as command-line arguments.
//
// A shell is a session on one asset, so the inventory must define exactly one.
// Discovery below that asset (an account's instances, a cluster's workloads)
// is still offered for interactive selection once it is connected.
func ShellInventory(asset *inventory.Asset, insecure bool, annotations map[string]string) (*inventory.Inventory, error) {
	inv, err := inventoryloader.ParseOrUse(asset, insecure, annotations)
	if err != nil {
		return nil, err
	}
	if n := len(inv.Spec.GetAssets()); n != 1 {
		return nil, errors.Newf("the shell connects to exactly one asset, but the inventory defines %d; "+
			"use an inventory with a single asset", n)
	}
	return inv, nil
}

// shellSelectItem is a selectable item in the interactive asset traversal.
// It wraps either a TrackedAsset (for navigation) or a "connect here" sentinel.
type shellSelectItem struct {
	tracked     *discovery.TrackedAsset // nil for the "connect here" option
	connectHere bool
	label       string
}

func (s shellSelectItem) Display() string {
	return s.label
}

// StartShell will start an interactive CLI shell using the AssetExplorer
// for lazy, caller-driven asset discovery.
func StartShell(runtime *providers.Runtime, conf *ShellConfig) error {
	ctx := context.Background()

	inv := conf.Inventory
	if inv == nil {
		inv = inventory.New(inventory.WithAssets(conf.Asset))
	}

	explorer, err := discovery.NewAssetExplorer(ctx, discovery.AssetExplorerConfig{
		Inventory: inv,
		Upstream:  conf.UpstreamConfig,
		Recording: runtime.Recording(),
	})
	if err != nil {
		log.Fatal().Err(err).Msg("could not process assets")
	}

	isTTY := isatty.IsTerminal(os.Stdout.Fd())

	// Select the asset to shell into via interactive traversal
	connectAsset, err := selectAsset(explorer, conf.PlatformID, isTTY)
	if err != nil {
		explorer.Shutdown()
		providers.Coordinator.Shutdown()
		log.Fatal().Err(err).Msg("asset selection failed")
	}

	if connectAsset == nil {
		explorer.Shutdown()
		providers.Coordinator.Shutdown()
		log.Error().Msg("no asset selected")
		os.Exit(1)
	}

	// Handle delayed discovery if needed
	if len(connectAsset.Asset.Connections) > 0 && connectAsset.Asset.Connections[0].DelayDiscovery {
		discoveredAsset, err := discovery.HandleDelayedDiscovery(ctx, connectAsset.Asset, connectAsset.Runtime)
		if err != nil {
			explorer.Shutdown()
			providers.Coordinator.Shutdown()
			log.Error().Msg("delayed discovery failed")
			os.Exit(1)
		}
		connectAsset.Asset = discoveredAsset
	}

	if connectAsset.Runtime != nil && connectAsset.Runtime.Provider.Connection != nil &&
		connectAsset.Runtime.Provider.Connection.Asset != nil &&
		connectAsset.Runtime.Provider.Connection.Asset.Platform != nil {
		log.Info().Msgf("connected to %s", connectAsset.Runtime.Provider.Connection.Asset.Platform.Title)
	}

	onCloseHandler := func() {
		explorer.Shutdown()
		providers.Coordinator.Shutdown()
	}

	// Create shell theme with custom welcome message if provided
	shellTheme := shell.DefaultShellTheme
	if conf.WelcomeMessage != "" {
		customTheme := *shellTheme
		customTheme.Welcome = conf.WelcomeMessage
		shellTheme = &customTheme
	}

	sh := shell.NewShell(
		connectAsset.Runtime,
		shell.WithOnClose(onCloseHandler),
		shell.WithFeatures(conf.Features),
		shell.WithStrict(conf.Strict),
		shell.WithUpstreamConfig(conf.UpstreamConfig),
		shell.WithTheme(shellTheme),
	)

	if err := sh.RunWithCommand(conf.Command); err != nil {
		if err == shell.ErrNotTTY {
			log.Fatal().Msg("shell requires an interactive terminal (TTY)")
		}
		log.Error().Err(err).Msg("shell error")
		return err
	}

	return nil
}

// selectAsset drives the interactive asset traversal using the AssetExplorer.
// It presents the user with discovered assets and lets them navigate the tree.
func selectAsset(explorer *discovery.AssetExplorer, platformID string, isTTY bool) (*discovery.TrackedAsset, error) {
	// Gather the initial set: connected roots + their discovered children
	candidates := gatherCandidates(explorer, platformID)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("could not find an asset that we can connect to")
	}

	// If there's exactly one candidate with no children to explore, use it directly
	if len(candidates) == 1 {
		asset := candidates[0]
		// Connect if not already connected
		if asset.State != discovery.AssetConnected {
			connected, err := explorer.Connect(asset)
			if err != nil {
				return nil, err
			}
			// If connecting revealed children, let the user choose
			if len(connected.Children) > 0 {
				return traverseAsset(explorer, connected, isTTY)
			}
			return connected, nil
		}
		if len(asset.Children) > 0 {
			return traverseAsset(explorer, asset, isTTY)
		}
		return asset, nil
	}

	// Multiple candidates: let the user pick
	if !isTTY {
		invAssets := make([]*inventory.Asset, 0, len(candidates))
		for _, a := range candidates {
			invAssets = append(invAssets, a.Asset)
		}
		log.Info().Msgf("discovered %d asset(s)", len(invAssets))
		fmt.Println(components.List(theme.OperatingSystemTheme, invAssets))
		return nil, fmt.Errorf("cannot connect to more than one asset, use --platform-id to select a specific asset")
	}

	selected := components.Select("Available assets", candidates)
	if selected < 0 {
		return nil, nil
	}

	asset := candidates[selected]

	// Connect if not already connected
	if asset.State != discovery.AssetConnected {
		connected, err := explorer.Connect(asset)
		if err != nil {
			return nil, err
		}
		if len(connected.Children) > 0 {
			return traverseAsset(explorer, connected, isTTY)
		}
		return connected, nil
	}

	// Already connected — check if it has children to traverse
	if len(asset.Children) > 0 {
		return traverseAsset(explorer, asset, isTTY)
	}
	return asset, nil
}

// traverseAsset presents the user with a choice: connect to the current asset
// or navigate into one of its children. Repeats until the user picks a leaf
// or chooses "Connect here".
func traverseAsset(explorer *discovery.AssetExplorer, current *discovery.TrackedAsset, isTTY bool) (*discovery.TrackedAsset, error) {
	if !isTTY {
		// Non-interactive: just use the current asset
		return current, nil
	}

	for {
		// Build selection list: "Connect here" + children
		items := make([]shellSelectItem, 0, len(current.Children)+1)
		items = append(items, shellSelectItem{
			connectHere: true,
			label:       fmt.Sprintf("» Connect to %s", current.Asset.HumanName()),
		})
		for _, child := range current.Children {
			items = append(items, shellSelectItem{
				tracked: child,
				label:   child.Asset.HumanName(),
			})
		}

		selected := components.Select(
			fmt.Sprintf("Asset %s has %d child asset(s)", current.Asset.HumanName(), len(current.Children)),
			items,
		)
		if selected < 0 {
			return nil, nil // user cancelled
		}

		choice := items[selected]
		if choice.connectHere {
			return current, nil
		}

		// User picked a child — connect to it and check for grandchildren
		child := choice.tracked
		if child.State != discovery.AssetConnected {
			connected, err := explorer.Connect(child)
			if err != nil {
				return nil, err
			}
			if len(connected.Children) > 0 {
				current = connected
				continue // loop to let user navigate deeper
			}
			return connected, nil
		}

		// Already connected
		if len(child.Children) > 0 {
			current = child
			continue
		}
		return child, nil
	}
}

// gatherCandidates returns the initial list of assets to present to the user.
// It includes connected roots and discovered children, optionally filtered by platform ID.
func gatherCandidates(explorer *discovery.AssetExplorer, platformID string) []*discovery.TrackedAsset {
	var candidates []*discovery.TrackedAsset

	// Include connected assets (roots) that have platform IDs
	for _, a := range explorer.Connected() {
		if len(a.Asset.PlatformIds) > 0 && matchesPlatformID(a, platformID) {
			candidates = append(candidates, a)
		}
	}

	// Include discovered children
	for _, a := range explorer.Discovered() {
		if matchesPlatformID(a, platformID) {
			candidates = append(candidates, a)
		}
	}

	return candidates
}

// matchesPlatformID returns true if the asset matches the given platform ID filter,
// or if the filter is empty (matches everything).
func matchesPlatformID(asset *discovery.TrackedAsset, platformID string) bool {
	if platformID == "" {
		return true
	}
	return slices.Contains(asset.Asset.PlatformIds, platformID)
}
