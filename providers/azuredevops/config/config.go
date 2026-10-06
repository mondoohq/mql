// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azuredevops/connection"
	"go.mondoo.com/mql/providers/azuredevops/provider"
)

var Config = plugin.Provider{
	Name: "azuredevops",
	ID:   "go.mondoo.com/mql/providers/azuredevops",
	Root: "azuredevops",
	// A pre-release: it is published to the preview channel until a first
	// customer scan has proven it.
	Version: "14.0.0-rc.1",
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.0"},
	},
	ConnectionTypes: []string{provider.ConnectionType},
	Connectors: []plugin.Connector{
		{
			Name:      "azuredevops",
			Use:       "azuredevops",
			Short:     "an Azure DevOps organization or repository",
			Discovery: []string{},
			Flags:     []plugin.Flag{},
		},
	},
	Platforms: connection.Platforms,
}
