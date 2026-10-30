// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/local"
)

func TestDockerfileRejectsADirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine\n"), 0o600))

	conf := &inventory.Config{Path: dir}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}

	// Handed a directory this used to build an asset literally named
	// "Dockerfile " whose platform ID hashed the directory path: a
	// plausible-looking asset describing nothing.
	_, err := NewDockerfileConnection(0, conf, asset, local.NewConnection(0, conf, asset), nil)
	require.Error(t, err)
	assert.True(t, plugin.IsNoMatchError(err), err)
}

func TestDockerfileAcceptsAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	require.NoError(t, os.WriteFile(path, []byte("FROM alpine\n"), 0o600))

	conf := &inventory.Config{Path: path}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}

	_, err := NewDockerfileConnection(0, conf, asset, local.NewConnection(0, conf, asset), nil)
	require.NoError(t, err)
	// The name and the identity come from the file, which is what a directory
	// silently failed to produce.
	assert.Equal(t, "Dockerfile Dockerfile", asset.Name)
	assert.NotEmpty(t, asset.PlatformIds)
}
