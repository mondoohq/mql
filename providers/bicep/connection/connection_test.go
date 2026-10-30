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
)

func newTestConnection(t *testing.T, path string) (*BicepConnection, error) {
	t.Helper()
	asset := &inventory.Asset{
		Connections: []*inventory.Config{
			{
				Type:    "bicep",
				Options: map[string]string{"path": path},
			},
		},
	}
	return NewBicepConnection(0, asset, asset.Connections[0])
}

func TestDiscoverBicepParamFilesInDirectory(t *testing.T) {
	dir := filepath.Join("..", "resources", "testdata", "paramfiles")
	conn, err := newTestConnection(t, dir)
	require.NoError(t, err)

	// The directory holds both a .bicep and a .bicepparam file; each must land
	// in its own bucket. A .bicepparam ends in "param", not ".bicep", so the
	// .bicep walker never picks it up.
	require.Len(t, conn.BicepParamFiles(), 1)
	assert.True(t, filepath.Base(conn.BicepParamFiles()[0].Path) == "prod.bicepparam")
	assert.Contains(t, conn.BicepParamFiles()[0].Content, "using './main.bicep'")

	require.Len(t, conn.BicepFiles(), 1)
	assert.Equal(t, "main.bicep", filepath.Base(conn.BicepFiles()[0].Path))
}

func TestDiscoverSingleBicepParamFile(t *testing.T) {
	path := filepath.Join("..", "resources", "testdata", "paramfiles", "prod.bicepparam")
	conn, err := newTestConnection(t, path)
	require.NoError(t, err)

	require.Len(t, conn.BicepParamFiles(), 1)
	assert.Equal(t, path, conn.BicepParamFiles()[0].Path)
	assert.Empty(t, conn.BicepFiles())
}

// writeFile writes content at dir/rel, creating parent directories.
func writeFile(t *testing.T, dir, rel, content string) string {
	t.Helper()
	path := filepath.Join(dir, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

const insecureStorageTemplate = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "stinsecure",
      "location": "eastus",
      "properties": { "supportsHttpsTrafficOnly": false }
    }
  ]
}`

// F1: an ARM template in a subdirectory must be discovered. `.bicep` files are
// already found recursively, so a template under `infra/` going missing makes
// every ARM policy pass vacuously.
func TestDiscoverARMTemplateInSubdirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.bicep", "param location string = 'eastus'\n")
	tmplPath := writeFile(t, dir, "infra/azuredeploy.json", insecureStorageTemplate)

	conn, err := newTestConnection(t, dir)
	require.NoError(t, err)

	require.NotNil(t, conn.ARMTemplate(), "template under infra/ must be discovered")
	require.Len(t, conn.ARMTemplates(), 1)
	assert.Equal(t, tmplPath, conn.ARMTemplates()[0].Path)
}

// F1: discovery must not be limited to four hardcoded filenames.
func TestDiscoverARMTemplateWithNonStandardName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.bicep", "param location string = 'eastus'\n")
	writeFile(t, dir, "arm/storage.prod.json", insecureStorageTemplate)

	conn, err := newTestConnection(t, dir)
	require.NoError(t, err)

	require.Len(t, conn.ARMTemplates(), 1)
	assert.Equal(t, "storage.prod.json", filepath.Base(conn.ARMTemplates()[0].Path))
}

// F1: every ARM template in the tree must be kept, each carrying its own path.
func TestDiscoverMultipleARMTemplates(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "azuredeploy.json", insecureStorageTemplate)
	writeFile(t, dir, "modules/network.json", insecureStorageTemplate)
	writeFile(t, dir, "modules/deploy.json", insecureStorageTemplate)

	conn, err := newTestConnection(t, dir)
	require.NoError(t, err)

	tmpls := conn.ARMTemplates()
	require.Len(t, tmpls, 3)
	// Deterministic, path-sorted order.
	bases := []string{
		filepath.Base(tmpls[0].Path),
		filepath.Base(tmpls[1].Path),
		filepath.Base(tmpls[2].Path),
	}
	assert.Equal(t, []string{"azuredeploy.json", "deploy.json", "network.json"}, bases)
}

// F1: a directory holding only an ARM template must connect. It previously
// failed with "no .bicep, .bicepparam, or ARM template JSON files found"
// whenever the template was not one of the four hardcoded root filenames.
func TestConnectARMTemplateOnlyDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "arm/deploy.json", insecureStorageTemplate)

	conn, err := newTestConnection(t, dir)
	require.NoError(t, err)
	require.NotNil(t, conn.ARMTemplate())
}

// F1: unrelated JSON in the tree must not be mistaken for an ARM template.
func TestNonTemplateJSONIsIgnored(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.bicep", "param location string = 'eastus'\n")
	writeFile(t, dir, "package.json", `{"name":"x","version":"1.0.0"}`)
	writeFile(t, dir, "broken.json", `{ this is not json `)

	conn, err := newTestConnection(t, dir)
	require.NoError(t, err)
	assert.Empty(t, conn.ARMTemplates())
	assert.Nil(t, conn.ARMTemplate())
}

const symbolicNameTemplate = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "languageVersion": "2.0",
  "contentVersion": "1.0.0.0",
  "resources": {
    "storageAccount": {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "stsymbolic",
      "location": "eastus",
      "properties": { "supportsHttpsTrafficOnly": false }
    },
    "appService": {
      "type": "Microsoft.Web/sites",
      "apiVersion": "2023-01-01",
      "name": "app-symbolic",
      "location": "eastus"
    }
  }
}`

// F2: `bicep build` emits languageVersion 2.0 templates whose `resources` is a
// JSON object keyed by symbolic name. Rejecting them wholesale skipped the
// entire template.
func TestLoadSymbolicNameTemplate(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.json", symbolicNameTemplate)

	conn, err := newTestConnection(t, dir)
	require.NoError(t, err)

	tmpl := conn.ARMTemplate()
	require.NotNil(t, tmpl, "a languageVersion 2.0 template must load")

	list := tmpl.ResourceList()
	require.Len(t, list, 2)
	// Symbolic-name order is deterministic (key-sorted).
	assert.Equal(t, "appService", list[0].SymbolicName)
	assert.Equal(t, "storageAccount", list[1].SymbolicName)
}

// F2: the classic array form must keep working, with an empty symbolic name.
func TestLoadArrayFormTemplate(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "azuredeploy.json", insecureStorageTemplate)

	conn, err := newTestConnection(t, dir)
	require.NoError(t, err)

	list := conn.ARMTemplate().ResourceList()
	require.Len(t, list, 1)
	assert.Empty(t, list[0].SymbolicName)
}

// F7: one unreadable directory must not abort the whole scan. The file-read
// path three lines below already logs and continues.
func TestUnreadableDirectoryDoesNotAbortScan(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := t.TempDir()
	writeFile(t, dir, "main.bicep", "param location string = 'eastus'\n")
	writeFile(t, dir, "sub/other.bicep", "param x string = 'y'\n")
	writeFile(t, dir, "azuredeploy.json", insecureStorageTemplate)

	locked := filepath.Join(dir, "locked")
	require.NoError(t, os.MkdirAll(locked, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(locked, "hidden.bicep"), []byte("param z string = 'q'\n"), 0o644))
	require.NoError(t, os.Chmod(locked, 0o000))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	conn, err := newTestConnection(t, dir)
	require.NoError(t, err, "an unreadable subdirectory must not make the asset unscannable")

	// The readable files are still found; only the locked subtree is skipped.
	require.Len(t, conn.BicepFiles(), 2)
	require.NotNil(t, conn.ARMTemplate())
}
