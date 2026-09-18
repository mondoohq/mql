// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func bicepAssetFor(path string) *inventory.Asset {
	return &inventory.Asset{Connections: []*inventory.Config{{
		Options: map[string]string{"path": path},
	}}}
}

func TestBicepRejectsAFolderWithNoBicep(t *testing.T) {
	dir := t.TempDir()
	// A .json file that is not an ARM template, so findARMTemplates' $schema
	// check is exercised too.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"),
		[]byte(`{"name":"app","version":"1.0.0"}`), 0o600))

	_, err := NewBicepConnection(0, bicepAssetFor(dir), &inventory.Config{})
	require.Error(t, err)
	assert.True(t, plugin.IsNoMatchError(err), err)
}

func TestBicepAcceptsABicepFolder(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.bicep"),
		[]byte("param location string = resourceGroup().location\n"), 0o600))

	_, err := NewBicepConnection(0, bicepAssetFor(dir), &inventory.Config{})
	assert.NoError(t, err)
}
