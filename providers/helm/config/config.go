// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/helm/provider"
)

var Config = plugin.Provider{
	Name: "helm",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "helm",
	ID:      "go.mondoo.com/mql/providers/helm",
	Version: "13.3.14",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.3.14"},
	},
	Maturity:        resources.MaturityExperimental,
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       provider.Platforms,
	Connectors: []plugin.Connector{
		{
			Name:  "helm",
			Use:   "helm PATH",
			Short: "a Helm chart directory or .tgz archive",
			Long: `Use the helm provider to query Helm charts, including chart metadata, templates, values, and rendered Kubernetes resources.

Examples:
  cnspec run helm ./my-chart -c "helm.charts { name version }"
  cnspec shell helm ./my-chart
`,
			MinArgs:   1,
			MaxArgs:   1,
			Discovery: []string{},
			Flags: []plugin.Flag{
				{
					Long: "values",
					Type: plugin.FlagType_List,
					Desc: "Values files to merge into the chart's values before rendering (repeatable, like helm --values)",
				},
				{
					Long: "set",
					Type: plugin.FlagType_List,
					Desc: "Override values on the command line (repeatable key=value, like helm --set)",
				},
				{
					Long: "set-string",
					Type: plugin.FlagType_List,
					Desc: "Override string values on the command line (repeatable key=value, like helm --set-string)",
				},
				{
					Long: "set-json",
					Type: plugin.FlagType_List,
					Desc: "Override values with JSON on the command line (repeatable key=json, like helm --set-json)",
				},
				{
					Long: "set-file",
					Type: plugin.FlagType_List,
					Desc: "Set a value from a file's contents (repeatable key=path, like helm --set-file)",
				},
				{
					Long: "release-name",
					Type: plugin.FlagType_String,
					Desc: "Release name used during rendering (defaults to the chart name)",
				},
				{
					Long:  "namespace",
					Short: "n",
					Type:  plugin.FlagType_String,
					Desc:  "Release namespace used during rendering (defaults to \"default\")",
				},
				{
					Long: "kube-version",
					Type: plugin.FlagType_String,
					Desc: "Target Kubernetes version for .Capabilities.KubeVersion during rendering",
				},
				{
					Long:  "api-versions",
					Short: "a",
					Type:  plugin.FlagType_List,
					Desc:  "Kubernetes API versions for .Capabilities.APIVersions.Has during rendering (repeatable)",
				},
				{
					Long:    "is-upgrade",
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Render with .Release.IsUpgrade set instead of .Release.IsInstall",
				},
				{
					Long: "repo",
					Type: plugin.FlagType_String,
					Desc: "Chart repository URL used to locate a chart referenced by name",
				},
				{
					Long: "version",
					Type: plugin.FlagType_String,
					Desc: "Chart version to pull when fetching a remote chart",
				},
				{
					Long: "username",
					Type: plugin.FlagType_String,
					Desc: "Username for the chart repository or OCI registry",
				},
				{
					Long:   "password",
					Type:   plugin.FlagType_String,
					Option: plugin.FlagOption_Password,
					Desc:   "Password for the chart repository or OCI registry",
				},
				{
					Long: "repository-config",
					Type: plugin.FlagType_String,
					Desc: "Path to the Helm repositories.yaml configuration",
				},
				{
					Long: "repository-cache",
					Type: plugin.FlagType_String,
					Desc: "Path to the Helm repository cache directory",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=iac", "category=helm"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"chart": nil,
			},
		},
	},
}
