// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

type ProvidersConf struct {
	Builtin []Builtin `json:"builtin"`

	providers []string // Providers names
}

// AddProvider registers a new builtin provider into the providers configuration
func (c *ProvidersConf) AddProvider(provider *resources.ProviderInfo) {
	if slices.Contains(c.Providers(), provider.Name) {
		return // provider already exist
	}

	// add provider
	c.Builtin = append(c.Builtin, Builtin{
		GoPackage: provider.Id,
		Name:      provider.Name,
		// Remote dependencies are not yet supported, we need to
		// modify this once we support them.
		// Remote:    provider.Remote,
	})

	// invalidate the internal list of providers since it changed
	c.providers = nil
}

func (c *ProvidersConf) Providers() []string {
	if len(c.providers) == 0 {
		for _, b := range c.Builtin {
			c.providers = append(c.providers, b.Name)
		}
	}
	return c.providers
}

type Builtin struct {
	Name      string
	Remote    string
	GoPackage string
}

func (b Builtin) Cwd() string {
	if b.Remote != "" {
		return b.Remote
	}

	return ""
}

func (b Builtin) Resource() string {
	if b.Remote != "" {
		return fmt.Sprintf("%s/resources/%s.resources.json", b.Remote, b.Name)
	}
	return "providers/" + b.Name + "/resources/" + b.Name + ".resources.json"
}

func (b Builtin) Dist() string {
	return "providers/" + b.Name + ".resources.json"
}

func (b Builtin) GoMod() string {
	if b.Remote != "" {
		return b.Remote + "/go.mod"
	}
	return "providers/" + b.Name + "/go.mod"
}

func (b *Builtin) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err == nil {
		b.Name = name
		b.GoPackage = "go.mondoo.com/mql/providers/" + name

		return nil
	}

	var raw struct {
		Name      string `json:"name"`
		Remote    string `json:"remote"`
		GoPackage string `json:"goPackage"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	b.Name = raw.Name
	b.Remote = raw.Remote
	if strings.HasPrefix(b.Remote, "~/") {
		b.Remote = os.ExpandEnv(strings.Replace(b.Remote, "~/", "$HOME/", 1))
	}

	b.GoPackage = raw.GoPackage

	return nil
}

func (b *Builtin) MarshalJSON() ([]byte, error) {
	if b.Remote == "" && b.GoPackage == "" {
		return json.Marshal(b.Name)
	}

	return json.Marshal(struct {
		Name      string `json:"name"`
		Remote    string `json:"remote"`
		GoPackage string `json:"goPackage"`
	}{
		Name:      b.Name,
		Remote:    b.Remote,
		GoPackage: b.GoPackage,
	})
}
