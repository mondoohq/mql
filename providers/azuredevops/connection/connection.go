// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/azuredevops.json so the CLI and generated docs can
// list what the provider supports. Add an entry here for every platform your
// asset discovery produces.
var Platforms = []*plugin.PlatformInfo{
	{Name: "azuredevops", Title: "Azure DevOps", Family: []string{"azuredevops"}, Kind: []string{"api"}, Runtime: []string{"azuredevops"}},
}

type AzuredevopsConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset
	// Add custom connection fields here
}

func NewAzuredevopsConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*AzuredevopsConnection, error) {
	conn := &AzuredevopsConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	// initialize your connection here

	return conn, nil
}

func (c *AzuredevopsConnection) Name() string {
	return "azuredevops"
}

func (c *AzuredevopsConnection) Asset() *inventory.Asset {
	return c.asset
}
