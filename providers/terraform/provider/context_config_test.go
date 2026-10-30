// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/terraform/connection"
)

func hclAsset(path string) *inventory.Asset {
	return &inventory.Asset{Connections: []*inventory.Config{{
		Type:    HclConnectionType,
		Options: map[string]string{"path": path},
	}}}
}

func TestAttachContextConfig(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "aws_s3_bucket" "b" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mondoo.yml"), []byte(`
token: committed-by-mistake
exceptions:
  - checks: [mondoo-terraform-aws-security-s3-bucket-logging]
    action: risk-accepted
    justification: central logging
`), 0o644))

	t.Run("directory", func(t *testing.T) {
		asset := hclAsset(dir)
		conn, err := connection.NewHclConnection(1, asset)
		require.NoError(t, err)

		attachContextConfig(asset, conn)
		require.NotNil(t, asset.ContextConfig)
		assert.Equal(t, ".", asset.ContextConfig.AssetPath)
		assert.Equal(t, "terraform", asset.ContextConfig.Origin.Provider)
		assert.Equal(t, filepath.Join(dir, "mondoo.yml"), asset.ContextConfig.Origin.Path)
		assert.Contains(t, string(asset.ContextConfig.Content), "central logging")
		// the credential never reaches the asset
		assert.NotContains(t, string(asset.ContextConfig.Content), "committed-by-mistake")
	})

	t.Run("single file reads its directory", func(t *testing.T) {
		asset := hclAsset(filepath.Join(dir, "main.tf"))
		conn, err := connection.NewHclConnection(1, asset)
		require.NoError(t, err)

		attachContextConfig(asset, conn)
		require.NotNil(t, asset.ContextConfig)
		assert.Equal(t, filepath.Join(dir, "mondoo.yml"), asset.ContextConfig.Origin.Path)
	})

	t.Run("no config", func(t *testing.T) {
		empty := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(empty, "main.tf"), []byte(`resource "aws_s3_bucket" "b" {}`), 0o644))
		asset := hclAsset(empty)
		conn, err := connection.NewHclConnection(1, asset)
		require.NoError(t, err)

		attachContextConfig(asset, conn)
		assert.Nil(t, asset.ContextConfig)
	})

	t.Run("a config set by the discovering provider is kept", func(t *testing.T) {
		asset := hclAsset(dir)
		asset.ContextConfig = &inventory.ContextConfig{Origin: &inventory.ConfigOrigin{Provider: "github"}}
		conn, err := connection.NewHclConnection(1, asset)
		require.NoError(t, err)

		attachContextConfig(asset, conn)
		assert.Equal(t, "github", asset.ContextConfig.Origin.Provider)
	})
}

func TestRepositoryFromURL(t *testing.T) {
	assert.Equal(t, "github.com/org/repo", repositoryFromURL("https://user:tok@github.com/org/repo.git"))
	assert.Equal(t, "gitlab.com/g/sub/repo", repositoryFromURL("https://gitlab.com/g/sub/repo"))
	assert.Equal(t, "", repositoryFromURL(""))
}
