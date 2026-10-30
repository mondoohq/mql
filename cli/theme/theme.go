// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package theme

import (
	"fmt"

	"github.com/muesli/termenv"
	"go.mondoo.com/mql/cli/printer"
	"go.mondoo.com/mql/cli/theme/colors"
)

// Theme to configure how the shell will look and feel
type Theme struct {
	Colors colors.Theme

	List          func(...string) string
	Landing       string
	PolicyPrinter printer.Printer
}

func (t Theme) Primary(s ...any) string {
	return termenv.String(fmt.Sprint(s...)).Foreground(t.Colors.Primary).String()
}

func (t Theme) Secondary(s ...any) string {
	return termenv.String(fmt.Sprint(s...)).Foreground(t.Colors.Secondary).String()
}

func (t Theme) Disabled(s ...any) string {
	return termenv.String(fmt.Sprint(s...)).Foreground(t.Colors.Disabled).String()
}

func (t Theme) Error(s ...any) string {
	return termenv.String(fmt.Sprint(s...)).Foreground(DefaultTheme.Colors.Error).String()
}

func (t Theme) Success(s ...any) string {
	return termenv.String(fmt.Sprint(s...)).Foreground(DefaultTheme.Colors.Success).String()
}

func (t Theme) Warn(s ...any) string {
	return termenv.String(fmt.Sprint(s...)).Foreground(DefaultTheme.Colors.Warn).String()
}

func (t Theme) Command(s ...any) string {
	return termenv.String(fmt.Sprint(s...)).Foreground(DefaultTheme.Colors.Command).String()
}
