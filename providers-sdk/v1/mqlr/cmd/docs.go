// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"go.mondoo.com/mql/providers-sdk/v1/mqlr/lrcore"
)

func init() {
	versionsCmd.Flags().String("versions-file", "", "optional path to the versions file (auto-detected if omitted)")
	versionsCmd.Flags().String("version", defaultVersionField, "provider version to assign to new entries")
	versionsCmd.Flags().String("license-header-file", "", "optional file path to read license header from")
	rootCmd.AddCommand(versionsCmd)
}

const defaultVersionField = "9.0.0"

var versionsCmd = &cobra.Command{
	Use:   "versions",
	Short: "generates or updates an .lr.versions file from an LR schema",
	Long:  `parse an LR file and generate a .lr.versions file tracking min_provider_version per resource and field.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		lrFile := args[0]

		versionsFilePath, err := cmd.Flags().GetString("versions-file")
		if err != nil {
			log.Fatal().Err(err).Msg("invalid argument for `versions-file`")
		}

		version, err := cmd.Flags().GetString("version")
		if err != nil {
			log.Fatal().Err(err).Msg("invalid argument for `version`")
		}

		headerFile, _ := cmd.Flags().GetString("license-header-file")

		runVersionsCmd(lrFile, headerFile, version, versionsFilePath)
	},
}

func runVersionsCmd(lrFile string, headerFile string, version string, versionsFilePath string) {
	if version == defaultVersionField {
		version = detectProviderVersion(lrFile)
	}

	raw, err := os.ReadFile(lrFile)
	if err != nil {
		log.Fatal().Err(err).Msg("could not read LR file")
	}

	res, err := lrcore.Parse(string(raw))
	if err != nil {
		log.Fatal().Err(err).Msg("could not parse LR file")
	}

	// Auto-detect versions file path if not provided
	if versionsFilePath == "" {
		versionsFilePath = strings.TrimSuffix(lrFile, ".lr") + ".lr.versions"
	}

	// Load existing versions if the file exists
	var existing lrcore.LrVersions
	_, err = os.Stat(versionsFilePath)
	if err == nil {
		log.Info().Msg("loading existing versions data")
		existing, err = lrcore.ReadVersions(versionsFilePath)
		if err != nil {
			log.Fatal().Err(err).Msg("could not read versions file " + versionsFilePath)
		}
	}

	versions := lrcore.GenerateVersions(res, version, existing)

	// Build license header template
	var headerTpl *template.Template
	if headerFile != "" {
		headerRaw, err := os.ReadFile(headerFile)
		if err != nil {
			log.Fatal().Err(err).Msg("could not read license header file")
		}
		headerTpl, err = template.New("license_header").Parse(string(headerRaw))
		if err != nil {
			log.Fatal().Err(err).Msg("could not parse license header template")
		}
	}

	if err := lrcore.WriteVersions(versionsFilePath, versions, headerTpl); err != nil {
		log.Fatal().Err(err).Msg("could not write versions file")
	}

	fmt.Printf("wrote %s (%d entries)\n", versionsFilePath, len(versions))
}
