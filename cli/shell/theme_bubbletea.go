// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shell

import (
	"github.com/charmbracelet/lipgloss"
	"go.mondoo.com/mql/cli/printer"
	"go.mondoo.com/mql/cli/theme"
)

// ShellTheme defines the visual appearance of the shell
type ShellTheme struct {
	// Input styling
	Prompt          lipgloss.Style
	MultilinePrompt lipgloss.Style
	InputText       lipgloss.Style

	// Completion popup
	PopupBorder         lipgloss.Style
	SuggestionNormal    lipgloss.Style
	SuggestionSelected  lipgloss.Style
	DescriptionNormal   lipgloss.Style
	DescriptionSelected lipgloss.Style
	ScrollIndicator     lipgloss.Style

	// Output
	OutputArea lipgloss.Style
	Error      lipgloss.Style
	Success    lipgloss.Style
	Secondary  lipgloss.Style
	Disabled   lipgloss.Style

	// Status
	Spinner  lipgloss.Style
	HelpBar  lipgloss.Style
	HelpKey  lipgloss.Style
	HelpText lipgloss.Style

	// Text content
	Welcome string
	Prefix  string

	// Printer for results
	PolicyPrinter printer.Printer
}

// Color constants matching the original theme
var (
	colorPurple   = lipgloss.Color("133") // Purple for prefix and selected items
	colorFuchsia  = lipgloss.Color("201") // Fuchsia for accents
	colorWhite    = lipgloss.Color("15")  // White for selected text
	colorRed      = lipgloss.Color("196") // Red for errors
	colorGreen    = lipgloss.Color("82")  // Green for success
	colorDisabled = lipgloss.Color("245") // Gray for disabled text
)

// DefaultShellTheme is the default theme for the shell
var DefaultShellTheme = &ShellTheme{
	// Input
	Prompt: lipgloss.NewStyle().
		Foreground(colorPurple).
		Bold(true),
	MultilinePrompt: lipgloss.NewStyle().
		Foreground(colorPurple),
	InputText: lipgloss.NewStyle(),

	// Completion popup
	PopupBorder: lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorPurple),
	SuggestionNormal: lipgloss.NewStyle().
		Foreground(lipgloss.Color("252")),
	SuggestionSelected: lipgloss.NewStyle().
		Foreground(colorWhite).
		Background(colorPurple).
		Bold(true),
	DescriptionNormal: lipgloss.NewStyle().
		Foreground(colorDisabled),
	DescriptionSelected: lipgloss.NewStyle().
		Foreground(colorWhite).
		Background(colorPurple),
	ScrollIndicator: lipgloss.NewStyle().
		Foreground(colorDisabled),

	// Output
	OutputArea: lipgloss.NewStyle().
		MarginTop(1),
	Error: lipgloss.NewStyle().
		Foreground(colorRed),
	Success: lipgloss.NewStyle().
		Foreground(colorGreen),
	Secondary: lipgloss.NewStyle().
		Foreground(colorPurple),
	Disabled: lipgloss.NewStyle().
		Foreground(colorDisabled),

	// Status
	Spinner: lipgloss.NewStyle().
		Foreground(colorFuchsia),
	HelpBar: lipgloss.NewStyle().
		Foreground(colorDisabled),
	HelpKey: lipgloss.NewStyle().
		Foreground(colorPurple).
		Bold(true),
	HelpText: lipgloss.NewStyle().
		Foreground(colorDisabled),

	// Text
	Welcome: "\n" + theme.Logo + "\n interactive shell\n",
	Prefix:  "> ",

	// Printer
	PolicyPrinter: printer.DefaultPrinter,
}

// Error formats a string as an error message
func (t *ShellTheme) ErrorText(s string) string {
	return t.Error.Render(s)
}

// SuccessText formats a string as a success message
func (t *ShellTheme) SuccessText(s string) string {
	return t.Success.Render(s)
}

// SecondaryText formats a string as secondary text
func (t *ShellTheme) SecondaryText(s string) string {
	return t.Secondary.Render(s)
}

// DisabledText formats a string as disabled/dimmed text
func (t *ShellTheme) DisabledText(s string) string {
	return t.Disabled.Render(s)
}
