// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"go.mondoo.com/mql/providers-sdk/v1/mqlr/lrcore"
)

var parseCmd = &cobra.Command{
	Use:   "parse",
	Short: "parse an LR file",
	Long:  `parse an LR file and print the AST`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		raw, err := os.ReadFile(args[0])
		if err != nil {
			log.Error().Msg(err.Error())
			return
		}

		res, err := lrcore.Parse(string(raw))
		if err != nil {
			log.Error().Msg(err.Error())
			return
		}

		s, _ := json.Marshal(res)
		fmt.Println(string(s))
	},
}

func init() {
	rootCmd.AddCommand(parseCmd)
}
