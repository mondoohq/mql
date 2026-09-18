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

func kustomizeAssetFor(path string) *inventory.Asset {
	return &inventory.Asset{Connections: []*inventory.Config{{
		Options: map[string]string{"path": path},
	}}}
}

func TestKustomizeRejectsAFolderWithNoKustomization(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "deployment.yaml"),
		[]byte("apiVersion: apps/v1\nkind: Deployment\n"), 0o600))

	_, err := NewKustomizeConnection(0, kustomizeAssetFor(dir), &inventory.Config{})
	require.Error(t, err)
	assert.True(t, plugin.IsNoMatchError(err), err)
}

func TestKustomizeRejectsAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kustomization.yaml")
	require.NoError(t, os.WriteFile(path, []byte("resources: []\n"), 0o600))

	// The opt-in is directory-scoped, so only a user naming a file lands here.
	_, err := NewKustomizeConnection(0, kustomizeAssetFor(path), &inventory.Config{})
	require.Error(t, err)
	assert.True(t, plugin.IsNoMatchError(err), err)
}

func TestKustomizeAcceptsAKustomization(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"),
		[]byte("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: []\n"), 0o600))

	_, err := NewKustomizeConnection(0, kustomizeAssetFor(dir), &inventory.Config{})
	assert.NoError(t, err)
}
