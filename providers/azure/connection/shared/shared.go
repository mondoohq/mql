// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type ConnectionType string

type AzureConnection interface {
	plugin.Connection
	Name() string
	Type() ConnectionType
	Config() *inventory.Config
	Asset() *inventory.Asset
}
