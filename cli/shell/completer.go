// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shell

import (
	"slices"
	"strings"

	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/utils/stringx"
)

// Suggestion represents a completion suggestion for the shell
type Suggestion struct {
	Text        string // The completion text
	Description string // Description shown in popup
}

// Completer is an auto-complete helper for the shell
type Completer struct {
	runtime  llx.Runtime
	features mql.Features
	strict   bool
	sortFn   func(a, b *llx.Documentation) int
}

// NewCompleter creates a new Mondoo completer object.
//
// It takes the runtime rather than a schema because completion compiles the
// partial input, and a compile is configured from a runtime: that is where the
// asset root comes from (ADR 031), along with the downgrade catalog and
// everything else NewConfigFrom carries. Building the config from a bare schema
// is what made the shell suggest a different set of names than it accepts -
// `hostname` ran but never completed.
func NewCompleter(runtime llx.Runtime, features mql.Features, strict bool, connectedProviders []string) *Completer {
	sortFn := byProviderSortFn(connectedProviders)

	return &Completer{
		runtime:  runtime,
		features: features,
		strict:   strict,
		sortFn:   sortFn,
	}
}

// builtinCommands are shell commands that should appear in completions
var builtinCommands = []Suggestion{
	{Text: "exit", Description: "Exit the shell"},
	{Text: "quit", Description: "Exit the shell"},
	{Text: "help", Description: "Show available resources"},
	{Text: "clear", Description: "Clear the screen"},
}

// Complete returns suggestions for the given input text
func (c *Completer) Complete(text string) []Suggestion {
	if text == "" {
		return nil
	}
	var suggestions []Suggestion

	// Check for matching built-in commands first (only at the start of input)
	for _, cmd := range builtinCommands {
		if strings.HasPrefix(cmd.Text, text) {
			suggestions = append(suggestions, cmd)
		}
	}

	bundle, _ := mqlc.Compile(text, nil, c.compilerConfig())
	if bundle != nil && len(bundle.Suggestions) > 0 {
		// reorder suggestions to put the ones from connected providers first
		slices.SortFunc(bundle.Suggestions, c.sortFn)

		// add suggestions from the compiler
		for i := range bundle.Suggestions {
			cur := bundle.Suggestions[i]
			suggestions = append(suggestions, Suggestion{
				Text:        cur.Field,
				Description: cur.Title,
			})
		}
	}

	return suggestions
}

func byProviderSortFn(connectedProviders []string) func(a, b *llx.Documentation) int {
	return func(a, b *llx.Documentation) int {
		aConnected := stringx.Contains(connectedProviders, a.Provider)
		bConnected := stringx.Contains(connectedProviders, b.Provider)
		if aConnected && !bConnected {
			return -1
		} else if !aConnected && bConnected {
			return 1
		}
		return 0
	}
}

func (c *Completer) compilerConfig() mqlc.CompilerConfig {
	conf := mqlc.NewConfigFrom(c.runtime, c.features)
	conf.Strict = c.strict
	// Interactive recompiles run on every keystroke, so keep non-fatal
	// advisories like the standalone where warning out of the terminal.
	conf.EditorMode = true
	return conf
}
