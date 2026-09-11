// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vllm/connection"
	"go.mondoo.com/mql/providers/vllm/provider"
)

var Config = plugin.Provider{
	Name: "vllm",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "vllm",
	ID:      "go.mondoo.com/mql/providers/vllm",
	Version: "13.0.23",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.23"},
	},
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       provider.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "vllm",
			Use:   "vllm ENDPOINT",
			Short: "a vLLM inference server",
			Long: `Use the vllm provider to assess the externally observable HTTP posture of a vLLM inference server.

Examples:
  mql shell vllm http://localhost:8000
  mql shell vllm https://vllm.example.com --api-key <token>

Notes:
  The provider probes remote HTTP routes only. Host-local flags, environment
  variables, LoRA resolver state, media allowlists, and internode network
  controls are outside this connector's observable scope.

Security:
  Only scan vLLM endpoints you are authorized to assess. The connector sends
  HTTP requests to the supplied URL, so templating that URL from untrusted data
  can create server-side request forgery risk. Explicit API-key credentials
  override VLLM_API_KEY from the environment.
`,
			MinArgs:   1,
			MaxArgs:   1,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long:    connection.OptionAPIKey,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Bearer token for authenticated comparison probes",
				},
				{
					Long:    "insecure",
					Type:    plugin.FlagType_Bool,
					Default: "",
					Desc:    "Disable TLS certificate verification",
				},
				{
					Long:    connection.OptionTimeout,
					Type:    plugin.FlagType_Int,
					Default: "10",
					Desc:    "HTTP request timeout in seconds",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=ai", "provider=vllm"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"server": nil,
			},
		},
	},
}
