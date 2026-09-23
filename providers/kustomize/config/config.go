// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/kustomize/provider"
)

var Config = plugin.Provider{
	Name: "kustomize",
	// Every kind this provider hands out as its own asset is a root (ADR 031).
	Root:    "kustomize",
	ID:      "go.mondoo.com/mql/providers/kustomize",
	Version: "14.0.0",
	// Every root carries `asset`, which core owns (ADR 042).
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.0"},
	},
	Maturity:        resources.MaturityExperimental,
	ConnectionTypes: []string{provider.DefaultConnectionType},
	Platforms:       provider.Platforms,
	// The exact set kustomizationFilenames recognizes, which is also what the
	// forge classifiers match.
	Targets: []plugin.TargetOptIn{
		{
			Target: "iac", Discovery: "kustomize", ConnType: provider.DefaultConnectionType, Auto: true,
			Match: []plugin.Matcher{
				{Glob: "kustomization.yaml"},
				{Glob: "kustomization.yml"},
				{Glob: "Kustomization"},
			},
		},
	},
	Connectors: []plugin.Connector{
		{
			Name:  "kustomize",
			Use:   "kustomize PATH",
			Short: "a Kustomize overlay directory",
			Long: `Use the kustomize provider to query Kustomize overlays, including patches, generators, image overrides, and rendered Kubernetes resources.

Examples:
  mql run kustomize ./overlays/production -c "kustomize.kustomizations { path namespace }"
  mql shell kustomize ./overlays/production
`,
			MinArgs:   1,
			MaxArgs:   1,
			Discovery: []string{},
			Flags:     []plugin.Flag{},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=iac", "category=kustomize"},
			Key:          "kind",
			Title:        "Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				"overlay": nil,
			},
		},
	},
}
