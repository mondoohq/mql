// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"os"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
	"go.mondoo.com/mql/cli/config"
	cli_errors "go.mondoo.com/mql/cli/errors"
	cliproviders "go.mondoo.com/mql/cli/providers"
	"go.mondoo.com/mql/cli/theme"
	"go.mondoo.com/mql/logger"
)

const (
	rootCmdDesc = "mql is a cloud-native tool for querying your entire infrastructure.\n"

	// we send a 78 exit code to prevent systemd service from restart
	ConfigurationErrorCode = 78
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mql",
	Short: "mql CLI",
	Long:  theme.DefaultTheme.Landing + "\n\n" + rootCmdDesc,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initLogger()
	},
}

func BuildRootCmd() (*cobra.Command, error) {
	err := cliproviders.AttachCLIs(
		rootCmd,
		&cliproviders.Command{
			Command: shellCmd,
			Run:     shellRun,
			Action:  "Interactive shell with ",
		},
		&cliproviders.Command{
			Command: RunCmd,
			Run:     RunCmdRun,
			Action:  "Run a query with ",
		},
		&cliproviders.Command{
			Command: DiscoverCmd,
			Run:     DiscoverCmdRun,
			Action:  "Discover assets with ",
		},
	)
	return rootCmd, err
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	_, err := BuildRootCmd()
	if err != nil {
		log.Error().Msg(err.Error())
		os.Exit(1)
	}

	if err := rootCmd.Execute(); err != nil {
		if cErr, ok := err.(*cli_errors.CommandError); ok {
			if cErr.HasError() {
				log.Error().Msg(err.Error())
			}
			os.Exit(cErr.ExitCode())
		}

		log.Error().Msg(err.Error())
		os.Exit(1)
	}
}

func init() {
	// NOTE: we need to call this super early, otherwise the CLI color output on Windows is broken for the first lines
	// since the log instance is already initialized, replace default zerolog color output with our own
	// use color logger by default
	logger.CliCompactLogger(logger.LogOutputWriter)
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// TODO harmonize with initLogger, which is called later and attached to the command
	// here we set the log level only by environment variable
	envLevel, ok := logger.GetEnvLogLevel()
	if ok {
		logger.Set(envLevel)
	}

	config.DefaultConfigFile = "mondoo.yml"

	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().String("log-level", "info", "Set the log level: error, warn, info, debug, trace")
	rootCmd.PersistentFlags().String("api-proxy", "", "Set the proxy for communications with Mondoo Platform API")
	rootCmd.PersistentFlags().Bool("auto-update", true, "Enable automatic provider installation and update")
	rootCmd.PersistentFlags().Bool("strict", false, "Require every link in an MQL chain to resolve; mark optional links with a question mark")
	// Set NoOptDefVal to allow space-separated bool values (--auto-update false)
	// Without this, "false" would be treated as a positional argument instead of the flag value
	rootCmd.PersistentFlags().Lookup("auto-update").NoOptDefVal = "true"
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	_ = viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level"))
	_ = viper.BindPFlag("api_proxy", rootCmd.PersistentFlags().Lookup("api-proxy"))
	_ = viper.BindPFlag("auto_update", rootCmd.PersistentFlags().Lookup("auto-update"))
	_ = viper.BindPFlag("strict", rootCmd.PersistentFlags().Lookup("strict"))
	_ = viper.BindEnv("features")
	_ = viper.BindEnv("strict")
	_ = viper.BindEnv("updates_url")
	_ = viper.BindEnv(config.KeyUpdateChannel)

	config.Init(rootCmd)
}

func initLogger() {
	// environment variables always over-write custom flags
	envLevel, ok := logger.GetEnvLogLevel()
	if ok {
		logger.Set(envLevel)
		return
	}

	// retrieve log-level from flags
	level := viper.GetString("log-level")
	if v := viper.GetBool("verbose"); v {
		level = "debug"
	}
	logger.Set(level)
}

var reMdName = regexp.MustCompile(`/([^/]+)\.md$`)

func GenerateMarkdown(dir string) error {
	rootCmd.DisableAutoGenTag = true

	// We need to remove our fancy logo from the markdown output,
	// since it messes with the formatting.
	rootCmd.Long = rootCmdDesc

	files := []string{}
	err := doc.GenMarkdownTreeCustom(rootCmd, dir, func(s string) string {
		files = append(files, s)

		titles := reMdName.FindStringSubmatch(s)
		if len(titles) == 0 {
			return ""
		}
		title := strings.ReplaceAll(titles[1], "_", " ")

		return "---\n" +
			"id: " + titles[1] + "\n" +
			"title: " + title + "\n" +
			"---\n\n"
	}, func(s string) string { return s })
	if err != nil {
		return err
	}

	// we need to remove the first headline, since it is doubled with the
	// headline from the ID. Really annoying, all this needs a rewrite.
	for i := range files {
		file := files[i]
		raw, err := os.ReadFile(file)
		if err != nil {
			return err
		}

		if !strings.HasPrefix(string(raw), "---\nid:") {
			continue
		}

		start := strings.Index(string(raw), "\n## ")
		if start < 0 {
			continue
		}

		end := start
		for i := start + 3; i < len(raw); i++ {
			if raw[i] == '\n' {
				end = i
				break
			}
		}

		res := append(raw[0:start], raw[end:]...)
		err = os.WriteFile(file, res, 0o644)
		if err != nil {
			return err
		}
	}

	return nil
}
