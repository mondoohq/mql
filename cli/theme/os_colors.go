// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package theme

import (
	"strings"

	"github.com/muesli/termenv"
	"go.mondoo.com/mql/cli/printer"
	"go.mondoo.com/mql/cli/theme/colors"
)

// OperatingSystemTheme for unix shell
var OperatingSystemTheme = &Theme{
	Colors: colors.DefaultColorTheme,
	List: func(items ...string) string {
		var w strings.Builder
		for i := range items {
			w.WriteString("- " + items[i] + "\n")
		}
		res := w.String()
		return res[0 : len(res)-1]
	},
	Landing:       termenv.String(Logo).Foreground(colors.DefaultColorTheme.Primary).String(),
	PolicyPrinter: printer.DefaultPrinter,
}
