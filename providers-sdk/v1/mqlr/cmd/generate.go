// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().String("dist", "", "folder for output LR and docs generation")
	generateCmd.MarkFlagRequired("dist") // nolint:errcheck
	generateCmd.Flags().Bool("fail-on-breaking", false, "fail if the schema change is breaking and has no migration (ADR 040 part 5)")
	generateCmd.Flags().Bool("fail-on-dep-drift", false, "fail if a peer dependency is undeclared or declared below what its references need (ADR 042)")
	generateCmd.Flags().String("providers-root", "", "directory holding the providers that name-based imports resolve against (default: derived from the .lr path)")
}

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "generates Go code and versions from an LR schema file",
	Long:  `parse an LR file and convert it to Go, then generates or updates the .lr.versions file. This is the equivalent of running the 'go' and 'versions' commands one after another.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dist, err := cmd.Flags().GetString("dist")
		if err != nil {
			log.Fatal().Err(err).Msg("failed to get dist flag")
		}

		if dist == "" {
			log.Fatal().Msg("dist flag is required")
		}

		failOnBreaking, _ := cmd.Flags().GetBool("fail-on-breaking")
		providersRoot, _ := cmd.Flags().GetString("providers-root")
		failOnDepDrift, _ := cmd.Flags().GetBool("fail-on-dep-drift")

		lrFile := args[0]
		headerFile := ""
		versionsFile := strings.TrimSuffix(lrFile, ".lr") + ".lr.versions"
		runGoCmd(lrFile, dist, headerFile, providersRoot, false, failOnBreaking, failOnDepDrift)
		runVersionsCmd(lrFile, headerFile, defaultVersionField, versionsFile)
	},
}
