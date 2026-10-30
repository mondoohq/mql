// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ollama

import (
	"encoding/json"
	"sort"
)

// Integration is one coding tool wired to this host's Ollama server, as
// recorded in a user's ~/.ollama/config.json.
type Integration struct {
	// Name is the key Ollama files the tool under, for example "claude",
	// "codex", or "opencode".
	Name string
	// Models are the model names the tool was configured with. They are what
	// the tool asks for, which is not necessarily what the host has: a name
	// here with no matching entry in the model store is a tool pointed at a
	// model that is not installed.
	Models []string
	// Aliases map a tool-side model name to an Ollama model name.
	Aliases map[string]string
	// Onboarded records whether the tool completed Ollama's setup flow.
	Onboarded bool
}

// integrationsFile is the shape of ~/.ollama/config.json. Only the fields that
// describe the wiring are read; the rest of the file is Ollama's own UI state.
type integrationsFile struct {
	Integrations map[string]*struct {
		Models    []string          `json:"models"`
		Aliases   map[string]string `json:"aliases"`
		Onboarded bool              `json:"onboarded"`
	} `json:"integrations"`
}

// ParseIntegrations reads the integrations recorded in a ~/.ollama/config.json.
// It returns them sorted by name so a query's output does not depend on Go's map
// ordering. Malformed JSON is an error; a file with no integrations is not.
func ParseIntegrations(data []byte) ([]Integration, error) {
	var f integrationsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	out := make([]Integration, 0, len(f.Integrations))
	for name, entry := range f.Integrations {
		if entry == nil {
			// A key present with a null value says the tool is known to Ollama
			// but carries no configuration. Report it rather than dropping it,
			// so the tool is still visible.
			out = append(out, Integration{Name: name})
			continue
		}
		out = append(out, Integration{
			Name:      name,
			Models:    entry.Models,
			Aliases:   entry.Aliases,
			Onboarded: entry.Onboarded,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ParseServerSettings reads ~/.ollama/server.json, which carries the one
// setting that is not an environment variable.
func ParseServerSettings(data []byte) (*ServerSettings, error) {
	var s ServerSettings
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
