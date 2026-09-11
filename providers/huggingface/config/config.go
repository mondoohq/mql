// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/huggingface/connection"
	"go.mondoo.com/mql/providers/huggingface/provider"
)

var Config = plugin.Provider{
	Name: "huggingface",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "huggingface",
	ID:      "go.mondoo.com/mql/providers/huggingface",
	Version: "13.1.15",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.1.15"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       connection.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "huggingface",
			Use:   "huggingface",
			Short: "Hugging Face",
			Long: `Use the huggingface provider to query models, datasets, and spaces on Hugging Face.

Examples:
  cnspec shell huggingface --token <API-TOKEN>
  cnspec shell huggingface --namespace openai --namespace-type org
  cnspec scan huggingface --namespace <USERNAME> --namespace-type user

Notes:
  If you set the HF_TOKEN environment variable, you can omit the token flag.
`,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long: "token",
					Type: plugin.FlagType_String,
					Desc: "Hugging Face API token (or set HF_TOKEN env var)",
				},
				{
					Long: "namespace",
					Type: plugin.FlagType_String,
					Desc: "Target a specific user or organization namespace (e.g. openai)",
				},
				{
					Long:    "namespace-type",
					Type:    plugin.FlagType_String,
					Default: "user",
					Desc:    "Type of the namespace: user or org",
				},
			},
		},
	},
}
