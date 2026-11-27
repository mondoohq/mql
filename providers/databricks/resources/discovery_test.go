// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/databricks/connection"
)

func TestDiscoveryDropsWarehouseID(t *testing.T) {
	// Synthetic: an account connection that carries a warehouse id.
	account := &inventory.Config{
		Type: "databricks",
		Options: map[string]string{
			connection.OptionPlane:       connection.PlaneAccount,
			connection.OptionAccountID:   "acc-1",
			connection.OptionClientID:    "client-1",
			connection.OptionWarehouseID: "wh-1",
		},
	}
	ws := workspaceConnectionConfig(account, 7, "https://ws.example.com", "123")

	_, hasWarehouse := ws.Options[connection.OptionWarehouseID]
	assert.False(t, hasWarehouse, "a warehouse belongs to one workspace and is not carried into discovered ones")
	_, hasAccount := ws.Options[connection.OptionAccountID]
	assert.False(t, hasAccount)
	assert.Equal(t, connection.PlaneWorkspace, ws.Options[connection.OptionPlane])
	assert.Equal(t, "https://ws.example.com", ws.Options[connection.OptionHost])
	assert.Equal(t, "123", ws.Options[connection.OptionWorkspaceID])
	assert.Equal(t, "client-1", ws.Options[connection.OptionClientID])
	assert.Equal(t, "wh-1", account.Options[connection.OptionWarehouseID], "the account connection keeps its own option")
}
