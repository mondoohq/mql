// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/inventory/manager"
)

// fakeShellPassword is a canary, not a credential. The tests compare against it
// without printing it, so a failure cannot leak a value from an inventory.
const fakeShellPassword = "canary-not-a-real-password"

const singleSSHInventory = `apiVersion: v1
kind: Inventory
metadata:
  name: shell-test
spec:
  assets:
    - name: ssh-target
      connections:
        - type: ssh
          host: 127.0.0.1
          port: 1
          credentials:
            - secret_id: ssh-password
  credentials:
    ssh-password:
      type: password
      user: tester
      password: ` + fakeShellPassword + `
`

const twoAssetInventory = `apiVersion: v1
kind: Inventory
metadata:
  name: shell-test
spec:
  assets:
    - name: first
      connections:
        - type: local
    - name: second
      connections:
        - type: local
`

// withInventoryFile writes data to a temporary inventory file and points the
// "inventory-file" viper key at it for the duration of the test.
func withInventoryFile(t *testing.T, data string) {
	t.Helper()
	path := ""
	if data != "" {
		path = filepath.Join(t.TempDir(), "inventory.yml")
		require.NoError(t, os.WriteFile(path, []byte(data), 0o600))
	}
	previous := viper.GetString("inventory-file")
	viper.Set("inventory-file", path)
	t.Cleanup(func() { viper.Set("inventory-file", previous) })
}

func cliAsset() *inventory.Asset {
	return &inventory.Asset{Name: "cli-target", Connections: []*inventory.Config{{Type: "local"}}}
}

func TestShellInventory_WithoutInventoryFileUsesTheCLIAsset(t *testing.T) {
	withInventoryFile(t, "")

	asset := cliAsset()
	inv, err := ShellInventory(asset, false, nil)
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 1)
	assert.Same(t, asset, inv.Spec.Assets[0])
}

func TestShellInventory_InventoryAssetReplacesTheCLIAsset(t *testing.T) {
	withInventoryFile(t, singleSSHInventory)

	inv, err := ShellInventory(cliAsset(), false, map[string]string{"team": "a"})
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 1)
	asset := inv.Spec.Assets[0]
	assert.Equal(t, "ssh-target", asset.Name)
	assert.Equal(t, "a", asset.Annotations["team"])

	// The asset only references the password; the inventory manager the asset
	// explorer uses resolves it from the credentials section that travels with
	// the inventory. Nothing has to come from the command line.
	require.Len(t, asset.Connections, 1)
	require.Len(t, asset.Connections[0].Credentials, 1)

	im, err := manager.NewManager(manager.WithInventory(inv, nil))
	require.NoError(t, err)
	resolved, err := im.ResolveAsset(asset)
	require.NoError(t, err)
	cred := resolved.Connections[0].Credentials[0]
	assert.Equal(t, "tester", cred.User)
	assert.True(t, string(cred.Secret) == fakeShellPassword || cred.Password == fakeShellPassword,
		"the password should resolve from the inventory's credentials section")
}

func TestShellInventory_InsecureMarksTheInventoryConnections(t *testing.T) {
	withInventoryFile(t, singleSSHInventory)

	inv, err := ShellInventory(cliAsset(), true, nil)
	require.NoError(t, err)
	assert.True(t, inv.Spec.Assets[0].Connections[0].Insecure)
}

func TestShellInventory_RejectsMoreThanOneAsset(t *testing.T) {
	withInventoryFile(t, twoAssetInventory)

	_, err := ShellInventory(cliAsset(), false, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one asset")
	assert.Contains(t, err.Error(), "defines 2")
}

func TestShellInventory_RejectsAnInvalidInventory(t *testing.T) {
	withInventoryFile(t, "spec: [this is not an inventory")

	_, err := ShellInventory(cliAsset(), false, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not parse inventory")
}

func TestShellInventory_RejectsAMissingInventoryFile(t *testing.T) {
	previous := viper.GetString("inventory-file")
	viper.Set("inventory-file", filepath.Join(t.TempDir(), "does-not-exist.yml"))
	t.Cleanup(func() { viper.Set("inventory-file", previous) })

	_, err := ShellInventory(cliAsset(), false, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not parse inventory")
}
