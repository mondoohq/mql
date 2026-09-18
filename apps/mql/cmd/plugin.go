// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"context"
	stderrors "errors"
	"os"

	"github.com/cockroachdb/errors"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/cli/printer"
	"go.mondoo.com/mql/cli/reporter"
	"go.mondoo.com/mql/cli/shell"
	"go.mondoo.com/mql/discovery"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/mqlc/parser"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/recording"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/shared"
	run "go.mondoo.com/mql/shared/proto"
	"go.mondoo.com/mql/utils/iox"
	"google.golang.org/protobuf/proto"
)

// pluginCmd represents the version command
var pluginCmd = &cobra.Command{
	Use:    "run_as_plugin",
	Hidden: true,
	Short:  "Run as a plugin",
	Run: func(cmd *cobra.Command, args []string) {
		goplugin.Serve(&goplugin.ServeConfig{
			HandshakeConfig: shared.Handshake,
			Plugins: map[string]goplugin.Plugin{
				"counter": &shared.MqlPlugin{Impl: &mqlPlugin{}},
			},

			// A non-nil value here enables gRPC serving for this plugin...
			GRPCServer: goplugin.DefaultGRPCServer,
		})
	},
}

func init() {
	rootCmd.AddCommand(pluginCmd)
}

type mqlPlugin struct{}

func (c *mqlPlugin) RunQuery(conf *run.RunQueryConfig, runtime *providers.Runtime, out iox.OutputHelper) error {
	if conf.Command == "" && conf.Input == "" {
		return errors.New("No command provided, nothing to do.")
	}

	opts, optsErr := config.Read()
	if optsErr != nil {
		log.Fatal().Err(optsErr).Msg("could not load configuration")
	}
	conf.Features = opts.GetFeatures()

	config.DisplayUsedConfig()

	if conf.DoParse {
		ast, err := parser.Parse(conf.Command)
		if err != nil {
			return errors.Wrap(err, "failed to parse command")
		}
		_ = out.WriteString(logger.PrettyJSON(ast))
		return nil
	}

	if conf.DoAst {
		compilerConf := mqlc.NewConfigFrom(runtime, conf.Features)
		compilerConf.Strict = conf.Strict
		b, err := mqlc.Compile(conf.Command, nil, compilerConf)
		if err != nil {
			return errors.Wrap(err, "failed to compile command")
		}

		_ = out.WriteString(logger.PrettyJSON((b)) + "\n" + printer.DefaultPrinter.CodeBundle(b))
		return nil
	}

	if conf.DoInfo {
		ast, err := parser.Parse(mqlc.Dedent(conf.Command))
		if ast == nil {
			return errors.Wrap(err, "failed to parse command")
		}

		compilerConf := mqlc.NewConfigFrom(runtime, conf.Features)
		compilerConf.Strict = conf.Strict
		compilerConf.EnableStats()
		conf := compilerConf
		_, err = mqlc.CompileAST(ast, nil, conf)
		if err != nil {
			return errors.Wrap(err, "failed to compile command")
		}

		_ = out.WriteString(printer.DefaultPrinter.CompilerStats(conf.Stats))
		return nil
	}

	var upstreamConfig *upstream.UpstreamConfig
	serviceAccount := opts.GetServiceCredential()
	if serviceAccount != nil {
		upstreamConfig = &upstream.UpstreamConfig{
			SpaceMrn:    opts.GetParentMrn(),
			ApiEndpoint: opts.UpstreamApiEndpoint(),
			ApiProxy:    opts.APIProxy,
			Incognito:   conf.Incognito,
			Creds:       serviceAccount,
		}
	}

	ctx := context.Background()

	// Enable staged discovery so providers can split discovery into phases
	for _, asset := range conf.Inventory.Spec.Assets {
		for _, conn := range asset.Connections {
			if conn.Options == nil {
				conn.Options = map[string]string{}
			}
			conn.Options[plugin.OptionStagedDiscovery] = ""
		}
	}

	explorer, err := discovery.NewAssetExplorer(ctx, discovery.AssetExplorerConfig{
		Inventory: conf.Inventory,
		Upstream:  upstreamConfig,
		Recording: runtime.Recording(),
	})
	if err != nil {
		return err
	}
	defer explorer.Shutdown()

	// Recursively connect all discovered assets depth-first
	connectAll(explorer, explorer.Discovered())
	allAssets := explorer.Connected()
	if err := noUsableAssetsError(len(allAssets), explorer.Errors()); err != nil {
		return err
	}

	if conf.Format == "json" {
		_ = out.WriteString("[")
	}

	// anyResultFailed is a flag that will be switched on if any query result failed,
	// if the flag `exit-1-on-failure` is provided and anyResultFailed is true, we
	// will exit the program with the exit code `1`
	anyResultFailed := false
	// Assets the query does not apply to. Counted rather than ignored: a run
	// where every asset was skipped produced no answers, and saying nothing
	// would let that read as a clean pass.
	skipped := 0
	// we defer this check since we want it to be the last thing to be evaluated
	defer func() {
		if conf.GetExit_1OnFailure() && anyResultFailed {
			os.Exit(1)
		}
	}()

	for i, tracked := range allAssets {
		if len(tracked.Asset.Connections) > 0 && tracked.Asset.Connections[0].DelayDiscovery {
			discoveredAsset, err := discovery.HandleDelayedDiscovery(ctx, tracked.Asset, tracked.Runtime)
			if err != nil {
				log.Error().Err(err).Str("asset", tracked.Asset.Name).Msg("failed to handle delayed discovery for asset")
				continue
			}
			tracked.Asset = discoveredAsset
		}

		// when we close the shell, we need to close the backend and store the recording
		onCloseHandler := func() {
			// FIXME: store recording
			// m.StoreRecording(viper.GetString("record-file"))
		}

		shellOptions := []shell.Option{}
		shellOptions = append(shellOptions, shell.WithOnClose(onCloseHandler))
		shellOptions = append(shellOptions, shell.WithFeatures(conf.Features))
		shellOptions = append(shellOptions, shell.WithStrict(conf.Strict))
		shellOptions = append(shellOptions, shell.WithOutput(out))
		// `run` is meant for non-interactive/scripted use, so we don't cap the
		// output like the interactive shell does. Users piping or processing the
		// full result set should get everything.
		shellOptions = append(shellOptions, shell.WithMaxLines(0))

		if upstreamConfig != nil {
			shellOptions = append(shellOptions, shell.WithUpstreamConfig(upstreamConfig))
		}

		sh := shell.NewShell(tracked.Runtime, shellOptions...)
		defer func() {
			// prevent the recording from being closed multiple times
			err = tracked.Runtime.SetRecording(recording.Null{})
			if err != nil {
				log.Error().Err(err).Msg("failed to set the recording layer to null")
			}
			sh.Close()
		}()

		var code *llx.CodeBundle
		var results map[string]*llx.RawResult
		if conf.Input != "" {
			var raw []byte
			raw, err = os.ReadFile(conf.Input)
			if err != nil {
				return errors.Wrap(err, "failed to read code bundle from file")
			}
			var b llx.CodeBundle
			if err = proto.Unmarshal(raw, &b); err != nil {
				return errors.Wrap(err, "failed to unmarshal code bundle")
			}
			code = &b
			results, err = sh.RunOnceBundle(code)
		} else {
			code, results, err = sh.RunOnce(conf.Command)
		}
		if err != nil {
			// A query that does not fit this asset's root is a statement about
			// which assets it targets, not a failure (ADR 031). Over a mixed
			// set - a k8s manifest yields a cluster, a namespace and a
			// deployment, each rooted differently - aborting on the first
			// mismatch would throw away every asset the query does apply to.
			// Skip it, and say so, so a skipped asset is never mistaken for one
			// that passed.
			if stderrors.Is(err, mqlc.ErrRootMismatch) {
				skipped++
				log.Info().Str("asset", tracked.Asset.GetName()).Err(err).
					Msg("skipping asset: this query does not apply to it")
				continue
			}
			return errors.Wrap(err, "failed to run")
		}

		// check if any result failed
		for _, result := range results {
			if result == nil || result.Data == nil {
				continue
			}

			if truthy, ok := result.Data.IsTruthy(); ok && !truthy {
				anyResultFailed = true
			}
		}

		if conf.Format == "llx" && conf.Output != "" {
			out, err := code.MarshalVT()
			if err != nil {
				return errors.Wrap(err, "failed to marshal code bundle")
			}
			err = os.WriteFile(conf.Output, out, 0o644)
			if err != nil {
				return errors.Wrap(err, "failed to save code bundle")
			}
			return nil
		}

		if conf.Format != "json" {
			sh.PrintResults(code, results)
		} else {
			_ = reporter.CodeBundleToJSON(code, results, out)
			if i < len(allAssets)-1 {
				_ = out.WriteString(",")
			}
		}
	}

	if conf.Format == "json" {
		_ = out.WriteString("]")
	}

	if skipped == len(allAssets) && skipped > 0 {
		return errors.Errorf("this query does not apply to any of the %d assets found", skipped)
	}
	if skipped > 0 {
		log.Info().Int("skipped", skipped).Int("total", len(allAssets)).
			Msg("some assets were skipped because the query does not apply to them")
	}

	return nil
}

// noUsableAssetsError reports the error to surface when not a single asset
// could be queried. Both asset runtime creation and asset connection log their
// failure and carry on, so that one unreachable asset does not abort a scan of
// many. The cost is that a run where *every* asset failed still reaches the
// query loop, finds nothing to iterate, and returns success. Anything
// scripting mql then cannot distinguish "all assets passed" from "no asset was
// ever scanned", so collapse that case into an error.
func noUsableAssetsError(connected int, assetErrors []*discovery.AssetWithError) error {
	if connected > 0 || len(assetErrors) == 0 {
		return nil
	}

	first := assetErrors[0]
	name := first.Asset.GetName()
	if name == "" {
		name = "<unnamed asset>"
	}
	if len(assetErrors) == 1 {
		return errors.Wrapf(first.Err, "could not connect to asset %s", name)
	}
	return errors.Wrapf(first.Err, "could not connect to any of the %d assets, first failure on %s", len(assetErrors), name)
}

// connectAll recursively connects all discovered assets depth-first,
// returning a flat list of connected assets.
func connectAll(explorer *discovery.AssetExplorer, assets []*discovery.TrackedAsset) []*discovery.TrackedAsset {
	var result []*discovery.TrackedAsset
	for _, asset := range assets {
		connected, err := explorer.Connect(asset)
		if err != nil {
			if !errors.Is(err, discovery.ErrDuplicateAsset) && !errors.Is(err, discovery.ErrNoMatch) {
				log.Error().Err(err).Str("asset", asset.Asset.Name).Msg("failed to connect to asset")
			}
			continue
		}
		result = append(result, connected)
		if len(connected.Children) > 0 {
			result = append(result, connectAll(explorer, connected.Children)...)
		}
	}
	return result
}
