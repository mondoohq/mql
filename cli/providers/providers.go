// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.mondoo.com/mql/v13/cli/components"
	"go.mondoo.com/mql/v13/cli/config"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/recording"
	"go.mondoo.com/mql/v13/types"
	"go.mondoo.com/mql/v13/utils/piped"
	"go.mondoo.com/ranger-rpc/status"
)

type Command struct {
	Command             *cobra.Command
	Run                 func(*cobra.Command, *providers.Runtime, *plugin.ParseCLIRes)
	Action              string
	SupportedConnectors []string
}

// AttachCLIs will attempt to parse the current commandline and look for providers.
// This step is done before cobra ever takes effect
func AttachCLIs(rootCmd *cobra.Command, commands ...*Command) error {
	existing, err := providers.ListActive()
	if err != nil {
		return err
	}

	connectorName, autoUpdate := detectConnectorName(os.Args, rootCmd, commands, existing)
	if connectorName != "" {
		if _, err := providers.EnsureProvider(providers.ProviderLookup{ConnName: connectorName}, autoUpdate, existing); err != nil {
			return err
		}
	}

	// Now that we know we have all providers, it's time to load them to build
	// the remaining CLI. Probably an opportunity to optimize in the future,
	// but fine for now to do it all.

	attachProviders(existing, commands)
	return nil
}

func detectConnectorName(args []string, rootCmd *cobra.Command, commands []*Command, existing providers.Providers) (string, bool) {
	autoUpdate := true

	config.InitViperConfig()

	// Determine the providers URL:
	// 1. If providers_url is explicitly set, use it (deprecated)
	// 2. Otherwise, if updates_url is set, use updates_url + "/providers"
	// 3. Otherwise, use the default
	if viper.IsSet("providers_url") {
		if providersURL := viper.GetString("providers_url"); providersURL != "" {
			updatesURL := strings.TrimSuffix(providersURL, "/providers")
			log.Warn().Msgf("providers_url is deprecated, please use updates_url: %s", updatesURL)
			providers.SetProviderRegistry(providers.NewMondooProviderRegistry(providers.WithBaseURL(providersURL)))
		}
	} else if viper.IsSet("updates_url") {
		if updatesURL := viper.GetString("updates_url"); updatesURL != "" {
			providers.SetProviderRegistry(providers.NewMondooProviderRegistry(providers.WithBaseURL(updatesURL + "/providers")))
		}
	}

	if viper.IsSet("auto_update") {
		autoUpdate = viper.GetBool("auto_update")
	}

	flags := pflag.NewFlagSet("set", pflag.ContinueOnError)
	flags.ParseErrorsAllowlist.UnknownFlags = true
	flags.Bool("auto-update", autoUpdate, "")
	flags.BoolP("help", "h", false, "")

	builtins := genBuiltinFlags()
	for i := range builtins {
		attachFlag(flags, builtins[i])
	}

	// To avoid warnings about flags, we need to mock all flags on the root command.
	// The command after root (eg: run, scan, shell, ...) are normal actions that
	// we want to detect. We only need to add flags from the root command and the
	// attaching subcommands (since those are the ones which end up giving us
	// the connector)
	attachPFlags(flags, rootCmd.Flags())
	attachPFlags(flags, rootCmd.PersistentFlags())

	for i := range commands {
		cmd := commands[i]
		attachPFlags(flags, cmd.Command.Flags())
	}

	for i := range existing {
		provider := existing[i]
		for j := range provider.Connectors {
			conn := provider.Connectors[j]
			for k := range conn.Flags {
				flag := conn.Flags[k]
				if found := flags.Lookup(flag.Long); found == nil {
					attachFlag(flags, flag)
				}
			}
		}
	}

	err := flags.Parse(args)
	if err != nil {
		log.Warn().Err(err).Msg("CLI pre-processing encountered an issue")
	}

	autoUpdate, _ = flags.GetBool("auto-update")

	parsedArgs := flags.Args()
	if len(parsedArgs) <= 1 {
		return "", autoUpdate
	}

	commandFound := false
	for j := range commands {
		if commands[j].Command.Use == parsedArgs[1] {
			commandFound = true
			break
		}
	}
	if !commandFound {
		return "", autoUpdate
	}

	// since we have a known command, we can now expect the connector to be
	// local by default if nothing else is set
	if len(parsedArgs) == 2 {
		return "local", autoUpdate
	}

	connector := parsedArgs[2]

	return connector, autoUpdate
}

func attachProviders(existing providers.Providers, commands []*Command) {
	for i := range commands {
		attachProvidersToCmd(existing, commands[i])
	}
}

func attachProvidersToCmd(existing providers.Providers, cmd *Command) {
	for i := range existing {
		provider := existing[i]
		for j := range provider.Connectors {
			conn := provider.Connectors[j]

			attach := true
			if len(cmd.SupportedConnectors) > 0 {
				attach = false // only attach if the connector is in the list
				for k := range cmd.SupportedConnectors {
					if cmd.SupportedConnectors[k] == conn.Name {
						attach = true
						break
					}
				}
			}
			if attach {
				attachConnectorCmd(provider.Provider, &conn, cmd)
			}
		}
	}

	// the default is always os.local if it exists
	if p, ok := existing.GetFirstID(providers.DefaultOsIDs...); ok {
		for i := range p.Connectors {
			c := p.Connectors[i]
			if c.Name == "local" {
				setDefaultConnector(p.Provider, &c, cmd)
				break
			}
		}
	}
}

func setDefaultConnector(provider *plugin.Provider, connector *plugin.Connector, cmd *Command) {
	cmd.Command.Run = func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			log.Error().Msg("provider " + args[0] + " does not exist")
			_ = cmd.Help()
			os.Exit(1)
		}

		log.Info().Msg("Connecting to your local system. To learn how to scan other platforms, use the --help flag.")
	}

	setConnector(provider, connector, cmd.Run, cmd.Command)
}

func attachConnectorCmd(provider *plugin.Provider, connector *plugin.Connector, cmd *Command) {
	res := &cobra.Command{
		Use:     connector.Use,
		Short:   cmd.Action + connector.Short,
		Long:    connector.Long,
		Aliases: connector.Aliases,
		PreRun:  cmd.Command.PreRun,
		PreRunE: cmd.Command.PreRunE,
		Hidden:  connector.IsHidden,
	}

	if connector.MinArgs == connector.MaxArgs {
		if connector.MinArgs == 0 {
			res.Args = cobra.NoArgs
		} else {
			res.Args = cobra.ExactArgs(int(connector.MinArgs))
		}
	} else {
		if connector.MaxArgs > 0 && connector.MinArgs == 0 {
			res.Args = cobra.MaximumNArgs(int(connector.MaxArgs))
		} else if connector.MaxArgs == 0 && connector.MinArgs > 0 {
			res.Args = cobra.MinimumNArgs(int(connector.MinArgs))
		} else {
			res.Args = cobra.RangeArgs(int(connector.MinArgs), int(connector.MaxArgs))
		}
	}
	cmd.Command.Flags().VisitAll(func(flag *pflag.Flag) {
		res.Flags().AddFlag(flag)
	})

	cmd.Command.AddCommand(res)
	setConnector(provider, connector, cmd.Run, res)
}

func genBuiltinFlags(discoveries ...string) []plugin.Flag {
	supportedDiscoveries := append([]string{"all", "auto"}, discoveries...)
	slices.Sort(supportedDiscoveries)

	return []plugin.Flag{
		// flags for providers:
		{
			Long: "discover",
			Type: plugin.FlagType_List,
			Desc: "Enable the discovery of nested assets. Supports: " + strings.Join(supportedDiscoveries, ", "),
		},
		{
			Long:   "pretty",
			Type:   plugin.FlagType_Bool,
			Desc:   "Pretty-print JSON",
			Option: plugin.FlagOption_Hidden,
		},
		// runtime-only flags:
		{
			Long: "record",
			Type: plugin.FlagType_String,
			Desc: "Record all resource calls and use resources in the recording",
		},
		{
			Long: "use-recording",
			Type: plugin.FlagType_String,
			Desc: "Use a recording to inject resource data (read-only)",
		},
	}
}

// the following flags are not processed by providers
var skipFlags = map[string]struct{}{
	"ask-pass":      {},
	"record":        {},
	"use-recording": {},
}

func attachPFlags(base *pflag.FlagSet, nu *pflag.FlagSet) {
	nu.VisitAll(func(flag *pflag.Flag) {
		if found := base.Lookup(flag.Name); found != nil {
			return
		}
		if flag.Shorthand != "" {
			if found := base.ShorthandLookup(flag.Shorthand); found != nil {
				return
			}
		}
		base.AddFlag(flag)
	})
}

func attachFlag(flagset *pflag.FlagSet, flag plugin.Flag) {
	// A provider must never be able to panic the whole CLI by declaring a
	// shorthand that a global flag (e.g. -f for output-format) already owns.
	// pflag's AddFlag panics on a duplicate shorthand, so drop the colliding
	// shorthand here and keep the long flag usable.
	if flag.Short != "" {
		if found := flagset.ShorthandLookup(flag.Short); found != nil {
			log.Warn().
				Str("flag", flag.Long).
				Str("shorthand", flag.Short).
				Str("conflicts-with", found.Name).
				Msg("provider flag shorthand already in use, ignoring shorthand")
			flag.Short = ""
		}
	}

	switch flag.Type {
	case plugin.FlagType_Bool:
		if flag.Short != "" {
			flagset.BoolP(flag.Long, flag.Short, json2T(flag.Default, false), flag.Desc)
		} else {
			flagset.Bool(flag.Long, json2T(flag.Default, false), flag.Desc)
		}
	case plugin.FlagType_Int:
		if flag.Short != "" {
			flagset.IntP(flag.Long, flag.Short, json2T(flag.Default, 0), flag.Desc)
		} else {
			flagset.Int(flag.Long, json2T(flag.Default, 0), flag.Desc)
		}
	case plugin.FlagType_String:
		if flag.Short != "" {
			flagset.StringP(flag.Long, flag.Short, flag.Default, flag.Desc)
		} else {
			flagset.String(flag.Long, flag.Default, flag.Desc)
		}
	case plugin.FlagType_List:
		if flag.Short != "" {
			flagset.StringSliceP(flag.Long, flag.Short, json2T(flag.Default, []string{}), flag.Desc)
		} else {
			flagset.StringSlice(flag.Long, json2T(flag.Default, []string{}), flag.Desc)
		}
	case plugin.FlagType_KeyValue:
		if flag.Short != "" {
			flagset.StringToStringP(flag.Long, flag.Short, json2T(flag.Default, map[string]string{}), flag.Desc)
		} else {
			flagset.StringToString(flag.Long, json2T(flag.Default, map[string]string{}), flag.Desc)
		}
	}

	if flag.Option&plugin.FlagOption_Hidden != 0 {
		_ = flagset.MarkHidden(flag.Long)
	}
	if flag.Option&plugin.FlagOption_Deprecated != 0 {
		_ = flagset.MarkDeprecated(flag.Long, "has been deprecated")
	}
}

func attachFlags(flagset *pflag.FlagSet, flags []plugin.Flag) {
	for i := range flags {
		attachFlag(flagset, flags[i])
	}
}

func markFlagsRequired(cmd *cobra.Command, flags []plugin.Flag) {
	askFlags := []string{}
	for _, f := range flags {
		if f.Option&plugin.FlagOption_Required != 0 {
			cmd.MarkFlagRequired(f.Long) // nolint:errcheck
		}
		if f.Option&plugin.FlagOption_AskInput != 0 {
			askFlags = append(askFlags, f.Long)
		}
	}
	if len(askFlags) > 0 {
		if cmd.Annotations == nil {
			cmd.Annotations = map[string]string{}
		}
		cmd.Annotations["ask-flags"] = strings.Join(askFlags, ",")
	}
}

func getFlagValueFromConfig(flag plugin.Flag) *llx.Primitive {
	switch flag.Type {
	case plugin.FlagType_Bool:
		return llx.BoolPrimitive(viper.GetBool(flag.Long))
	case plugin.FlagType_Int:
		return llx.IntPrimitive(viper.GetInt64(flag.Long))
	case plugin.FlagType_String:
		return llx.StringPrimitive(viper.GetString(flag.Long))
	case plugin.FlagType_List:
		return llx.ArrayPrimitiveT(viper.GetStringSlice(flag.Long), llx.StringPrimitive, types.String)
	case plugin.FlagType_KeyValue:
		return llx.MapPrimitiveT(viper.GetStringMapString(flag.Long), llx.StringPrimitive, types.String)
	default:
		log.Warn().Msg("unknown flag type for " + flag.Long)
		return nil
	}
}

// lookupFlagEnv checks for a MONDOO_<FLAG> environment variable directly,
// bypassing viper. This avoids picking up config-file values that happen
// to share the same key name (e.g. a provider's --token flag vs. the
// platform SA token in mondoo.yml).
func lookupFlagEnv(flag plugin.Flag) (envKey string, val string, ok bool) {
	replacer := strings.NewReplacer("-", "_", ".", "_")
	envKey = "MONDOO_" + strings.ToUpper(replacer.Replace(flag.Long))
	val, ok = os.LookupEnv(envKey)
	return envKey, val, ok
}

func getFlagValueFromCobra(flag plugin.Flag, cmd *cobra.Command) *llx.Primitive {
	var err error
	switch flag.Type {
	case plugin.FlagType_Bool:
		if v, err := cmd.Flags().GetBool(flag.Long); err == nil {
			return llx.BoolPrimitive(v)
		}
	case plugin.FlagType_Int:
		if v, err := cmd.Flags().GetInt(flag.Long); err == nil {
			return llx.IntPrimitive(int64(v))
		}
	case plugin.FlagType_String:
		if v, err := cmd.Flags().GetString(flag.Long); err == nil {
			return llx.StringPrimitive(v)
		}
	case plugin.FlagType_List:
		if v, err := cmd.Flags().GetStringSlice(flag.Long); err == nil {
			return llx.ArrayPrimitiveT(v, llx.StringPrimitive, types.String)
		}
	case plugin.FlagType_KeyValue:
		if v, err := cmd.Flags().GetStringToString(flag.Long); err == nil {
			return llx.MapPrimitiveT(v, llx.StringPrimitive, types.String)
		}
	default:
		log.Warn().Msg("unknown flag type for " + flag.Long)
		return nil
	}

	log.Warn().Err(err).Msg("failed to get flag " + flag.Long)
	return nil
}

func setConnector(provider *plugin.Provider, connector *plugin.Connector, run func(*cobra.Command, *providers.Runtime, *plugin.ParseCLIRes), cmd *cobra.Command) {
	oldRun := cmd.Run
	oldPreRun := cmd.PreRun

	builtinFlags := genBuiltinFlags(connector.Discovery...)
	allFlags := append(connector.Flags, builtinFlags...)

	cmd.PreRun = func(cc *cobra.Command, args []string) {
		if oldPreRun != nil {
			oldPreRun(cc, args)
		}

		// Config options need to be connected to flags before the Run begins.
		// Flags are provided by the connector.
		for i := range allFlags {
			flag := allFlags[i]
			// Skip flags that opt out of config binding ("-") and flags
			// that have no explicit config entry. Binding flags with no
			// ConfigEntry would use the flag name as the viper key, which
			// can collide with top-level config keys (e.g. a provider's
			// --token flag overwrites the platform service-account token,
			// causing 401 on upstream API calls).
			if flag.ConfigEntry == "-" || flag.ConfigEntry == "" {
				log.Debug().Msg("skipping config binding for " + flag.Long)
				continue
			}

			_ = viper.BindPFlag(flag.ConfigEntry, cmd.Flags().Lookup(flag.Long))
		}
	}

	cmd.Run = func(cc *cobra.Command, args []string) {
		if oldRun != nil {
			oldRun(cc, args)
		}

		log.Debug().Msg("using provider " + provider.Name + " with connector " + connector.Name)

		// this is the builtin ask-password flag. we should eventually remove this in favour
		// of an explicit ask-password flag on the provider connector that is marked with AskInput
		askPass, err := cc.Flags().GetBool("ask-pass")
		if err == nil && askPass {
			pass, err := components.AskPassword("Enter password: ")
			if err != nil {
				log.Fatal().Err(err).Msg("failed to get password")
			}
			_ = cc.Flags().Set("password", pass)
		}

		askFlags := cc.Annotations["ask-flags"]
		askFLagsList := strings.SplitSeq(askFlags, ",")
		for f := range askFLagsList {
			ask, err := cc.Flags().GetBool(f)
			if err == nil && ask {
				ask := strings.TrimPrefix(f, "ask-")
				input, err := components.AskPassword(fmt.Sprintf("Enter value for %s: ", ask))
				if err != nil {
					log.Fatal().Err(err).Msg("failed to get input for " + f)
				}
				cc.Flags().Set(ask, input) //nolint:errcheck
			}
		}
		useRecording, err := cc.Flags().GetString("use-recording")
		if err != nil {
			log.Warn().Msg("failed to get flag --recording")
		}
		record, err := cc.Flags().GetString("record")
		if err != nil {
			log.Warn().Msg("failed to get flag --record")
		}
		pretty, err := cc.Flags().GetBool("pretty")
		if err != nil {
			log.Warn().Msg("failed to get flag --pretty")
		}

		flagVals := map[string]*llx.Primitive{}
		for i := range allFlags {
			flag := allFlags[i]

			// we skip these because they are coded above
			if _, skip := skipFlags[flag.Long]; skip {
				continue
			}

			switch flag.ConfigEntry {
			case "-":
				// Opted out of config entirely — read from cobra only.
				if v := getFlagValueFromCobra(flag, cmd); v != nil {
					flagVals[flag.Long] = v
				}
			case "":
				// No explicit config mapping. Use cobra when the user
				// passed the flag on the CLI; otherwise check for a
				// MONDOO_<FLAG> env var directly (not through viper,
				// since viper.GetString would also pick up config-file
				// values that happen to share the same key name).
				if cmd.Flags().Changed(flag.Long) {
					if v := getFlagValueFromCobra(flag, cmd); v != nil {
						flagVals[flag.Long] = v
					}
				} else if envKey, envVal, ok := lookupFlagEnv(flag); ok {
					if err := cmd.Flags().Set(flag.Long, envVal); err != nil {
						log.Warn().Err(err).Str("flag", flag.Long).Str("env", envKey).Msg("invalid env value for flag")
					}
					if v := getFlagValueFromCobra(flag, cmd); v != nil {
						flagVals[flag.Long] = v
					}
				}
			default:
				if v := getFlagValueFromConfig(flag); v != nil {
					flagVals[flag.Long] = v
				}
			}
		}

		// TODO: add flag to set timeout and then use RuntimeWithShutdownTimeout
		runtime := providers.Coordinator.NewRuntime()
		if err = providers.SetDefaultRuntime(runtime); err != nil {
			log.Error().Msg(err.Error())
		}

		autoUpdate := true
		if viper.IsSet("auto_update") {
			autoUpdate = viper.GetBool("auto_update")
		}

		runtime.AutoUpdate = providers.UpdateProvidersConfig{
			Enabled:         autoUpdate,
			RefreshInterval: 60 * 60,
		}

		if err := runtime.UseProvider(provider.ID); err != nil {
			providers.Coordinator.Shutdown()
			log.Fatal().Err(err).Msg("failed to start provider " + provider.Name)
		}

		if record != "" && useRecording != "" {
			providers.Coordinator.Shutdown()
			log.Fatal().Msg("please only use --record or --use-recording, but not both at the same time")
		}
		recordingPath := record
		if recordingPath == "" {
			recordingPath = useRecording
		}
		doRecord := record != ""

		recording, err := recording.NewWithFile(recordingPath, recording.RecordingOptions{
			DoRecord:        doRecord,
			PrettyPrintJSON: pretty,
		})
		if err != nil {
			providers.Coordinator.Shutdown()
			log.Fatal().Msg(err.Error())
		}
		_ = runtime.SetRecording(recording)

		cliRes, err := runtime.Provider.Instance.Plugin.ParseCLI(&plugin.ParseCLIReq{
			Connector: connector.Name,
			Args:      args,
			Flags:     flagVals,
		})
		if err != nil {
			runtime.Close()
			providers.Coordinator.Shutdown()
			s, ok := status.FromError(err)
			if ok {
				log.Error().Msg(s.Message())
			} else {
				log.Error().Err(err).Msg("failed to parse cli arguments")
			}
			_ = cmd.Help()
			return
		}

		if cliRes == nil {
			runtime.Close()
			providers.Coordinator.Shutdown()
			log.Fatal().Msg("failed to process CLI arguments, nothing was returned")
			return // adding this here as a compiler hint to stop warning about nil-dereferences
		}

		temporaryFiles := []string{}
		if cliRes.Asset == nil {
			log.Warn().Err(err).Msg("failed to discover assets after processing CLI arguments")
		} else {
			// Enable staged discovery for all provider connections so that
			// providers that support it can split discovery into phases.
			for _, conf := range cliRes.Asset.Connections {
				if conf.Options == nil {
					conf.Options = map[string]string{}
				}
				conf.Options[plugin.OptionStagedDiscovery] = ""
			}

			// if we have an asset, we check if the path requires piped content
			for _, conf := range cliRes.Asset.Connections {
				if conf.Path != "-" {
					continue
				}

				// we need to read from stdin
				data, ok := piped.LoadDataFromPipe()
				if !ok {
					log.Fatal().Msg("could not load data from piped input")
				}
				// generate a new temporary file and write the content to it
				tmpFile, err := os.CreateTemp("", "mql-stdin-")
				if err != nil {
					log.Fatal().Err(err).Msg("could not create temporary file for stdin")
				}
				// remove temporary file after the runtime is closed
				log.Info().Str("file", tmpFile.Name()).Msg("created temporary file for stdin")
				temporaryFiles = append(temporaryFiles, tmpFile.Name())
				if _, err := tmpFile.Write(data); err != nil {
					log.Fatal().Err(err).Str("file", tmpFile.Name()).Msg("could not write data to temporary file")
				}

				// replace path with the temporary file and set a flag to indicate that it is piped content
				conf.Path = tmpFile.Name()
				if conf.Options == nil {
					conf.Options = map[string]string{}
				}
				conf.Options["piped"] = "true"
			}

			// NOTE: no fatal output beyond this point, so that the runtime is closed properly
			assetRuntime, err := providers.Coordinator.RuntimeFor(cliRes.Asset, runtime)
			if err != nil {
				log.Warn().Err(err).Msg("failed to get runtime for an asset that was detected after parsing the CLI")
			} else {
				runtime = assetRuntime
			}
		}

		run(cc, runtime, cliRes)
		runtime.Close()
		providers.Coordinator.Shutdown()

		// remove optional temporary files
		for _, tmpFile := range temporaryFiles {
			_ = os.Remove(tmpFile)
		}
	}

	attachFlags(cmd.Flags(), allFlags)
	// mark all required flags
	markFlagsRequired(cmd, allFlags)
}

func json2T[T any](s string, empty T) T {
	var res T
	if err := json.Unmarshal([]byte(s), &res); err == nil {
		return res
	}
	return empty
}
