// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/cli/inventoryloader"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/shared/proto"
	"go.mondoo.com/mql/utils/iox"
)

func init() {
	rootCmd.AddCommand(RunCmd)

	_ = RunCmd.Flags().StringP("command", "c", "", "MQL query to execute")
	_ = RunCmd.Flags().Bool("parse", false, "Parse the query and return the logical structure")
	_ = RunCmd.Flags().Bool("ast", false, "Parse the query and return the abstract syntax tree (AST)")
	_ = RunCmd.Flags().Bool("info", false, "Parse the query and provide information about it")
	_ = RunCmd.Flags().BoolP("json", "j", false, "Run the query and return the object in a JSON structure")
	_ = RunCmd.Flags().String("platform-id", "", "Select a specific target asset by providing its platform ID")
	_ = RunCmd.Flags().String("inventory-file", "", "Set the path to the inventory file")

	_ = RunCmd.Flags().String("llx", "", "Generate the executable code bundle and save it to the specified file")
	_ = RunCmd.Flags().MarkHidden("llx")
	_ = RunCmd.Flags().String("use-llx", "", "Run the code specified in the code bundle on disk")
	_ = RunCmd.Flags().MarkHidden("use-llx")
	_ = RunCmd.Flags().StringToString("annotations", nil, "Specify annotations for this run")
	_ = RunCmd.Flags().MarkHidden("annotations")
	_ = RunCmd.Flags().Bool("exit-1-on-failure", false, "Exit with error code 1 if one or more query results fail")
}

var RunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run an MQL query",
	Long:  `Run an MQL query on the CLI and display its results.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		_ = viper.BindPFlag("platform-id", cmd.Flags().Lookup("platform-id"))
		_ = viper.BindPFlag("annotations", cmd.Flags().Lookup("annotations"))
		_ = viper.BindPFlag("inventory-file", cmd.Flags().Lookup("inventory-file"))
	},
	// we have to initialize an empty run so it shows up as a runnable command in --help
	Run: func(cmd *cobra.Command, args []string) {},
}

var RunCmdRun = func(cmd *cobra.Command, runtime *providers.Runtime, cliRes *plugin.ParseCLIRes) {
	conf := proto.RunQueryConfig{}

	conf.Command, _ = cmd.Flags().GetString("command")
	conf.DoAst, _ = cmd.Flags().GetBool("ast")
	conf.DoInfo, _ = cmd.Flags().GetBool("info")
	conf.DoParse, _ = cmd.Flags().GetBool("parse")
	conf.Exit_1OnFailure, _ = cmd.Flags().GetBool("exit-1-on-failure")
	conf.Strict = config.Strict
	if doJSON, _ := cmd.Flags().GetBool("json"); doJSON {
		conf.Format = "json"
	}
	if llx, _ := cmd.Flags().GetString("llx"); llx != "" {
		conf.Format = "llx"
		conf.Output = llx
	}
	if llx, _ := cmd.Flags().GetString("use-llx"); llx != "" {
		conf.Input = llx
	}

	conf.PlatformId, _ = cmd.Flags().GetString("platform-id")
	annotations, _ := cmd.Flags().GetStringToString("annotations")
	if annotations == nil {
		annotations = map[string]string{}
	}
	cliRes.Asset.AddAnnotations(annotations)

	// required to resolve secrets
	in, err := inventoryloader.ParseOrUse(cliRes.Asset, viper.GetBool("insecure"), annotations)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to resolve inventory")
	}

	conf.Inventory = in
	conf.Incognito, _ = cmd.Flags().GetBool("incognito")

	x := mqlPlugin{}
	w := iox.IOWriter{Writer: os.Stdout}
	err = x.RunQuery(&conf, runtime, &w)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to run query")
	}
}
