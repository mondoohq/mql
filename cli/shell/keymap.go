// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shell

import "strings"

import "github.com/charmbracelet/bubbles/key"

// KeyMap defines key bindings for the shell
type KeyMap struct {
	// Basic navigation
	Submit    key.Binding
	Exit      key.Binding
	Cancel    key.Binding
	Clear     key.Binding
	ShowHelp  key.Binding
	AssetInfo key.Binding
	Newline   key.Binding

	// History
	HistorySearch key.Binding

	// Completion navigation
	NextCompletion   key.Binding
	PrevCompletion   key.Binding
	AcceptCompletion key.Binding
	DismissPopup     key.Binding
}

// DefaultKeyMap returns the default key bindings
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Submit: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "execute query"),
		),
		Exit: key.NewBinding(
			key.WithKeys("ctrl+d"),
			key.WithHelp("ctrl+d", "exit shell"),
		),
		Cancel: key.NewBinding(
			key.WithKeys("ctrl+c"),
			key.WithHelp("ctrl+c", "cancel/clear input"),
		),
		Clear: key.NewBinding(
			key.WithKeys("ctrl+l"),
			key.WithHelp("ctrl+l", "clear screen"),
		),
		ShowHelp: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "show keybindings"),
		),
		AssetInfo: key.NewBinding(
			key.WithKeys("ctrl+o"),
			key.WithHelp("ctrl+o", "show asset info"),
		),
		Newline: key.NewBinding(
			key.WithKeys("ctrl+j"),
			key.WithHelp("ctrl+j", "insert newline"),
		),
		HistorySearch: key.NewBinding(
			key.WithKeys("ctrl+r"),
			key.WithHelp("ctrl+r", "search history"),
		),
		NextCompletion: key.NewBinding(
			key.WithKeys("down", "tab"),
			key.WithHelp("↓/tab", "next suggestion"),
		),
		PrevCompletion: key.NewBinding(
			key.WithKeys("up", "shift+tab"),
			key.WithHelp("↑/shift+tab", "previous suggestion"),
		),
		AcceptCompletion: key.NewBinding(
			key.WithKeys("enter", "tab"),
			key.WithHelp("enter/tab", "accept suggestion"),
		),
		DismissPopup: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "dismiss suggestions"),
		),
	}
}

// ShortHelp returns keybindings to show in the mini help view
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Submit, k.Exit, k.ShowHelp}
}

// FullHelp returns keybindings for the expanded help view
func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Submit, k.Exit, k.Cancel, k.Clear, k.ShowHelp},
		{k.AssetInfo, k.Newline, k.HistorySearch},
		{k.NextCompletion, k.PrevCompletion, k.AcceptCompletion, k.DismissPopup},
	}
}

// FormatFullHelp returns a formatted string of all keybindings
func (k KeyMap) FormatFullHelp() string {
	sections := []struct {
		title    string
		bindings []key.Binding
	}{
		{"General", []key.Binding{k.Submit, k.Exit, k.Cancel, k.Clear, k.ShowHelp}},
		{"Editing", []key.Binding{k.Newline, k.HistorySearch, k.AssetInfo}},
		{"Suggestions", []key.Binding{k.NextCompletion, k.PrevCompletion, k.AcceptCompletion, k.DismissPopup}},
	}

	var result strings.Builder
	for _, section := range sections {
		result.WriteString("\n  " + section.title + ":\n")
		for _, b := range section.bindings {
			help := b.Help()
			result.WriteString("    " + help.Key + " - " + help.Desc + "\n")
		}
	}
	return result.String()
}
