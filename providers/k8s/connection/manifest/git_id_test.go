// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package manifest_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
)

// cloneOf copies the test manifest into a fresh directory, standing in for one
// scan's temporary git clone, and connects to it as a clone of gitURL.
func cloneOf(t *testing.T, gitURL string) shared.Connection {
	t.Helper()
	data, err := os.ReadFile("./testdata/valid/deployment.yaml")
	require.NoError(t, err)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "deployment.yaml"), data, 0o600))

	asset := &inventory.Asset{
		Platform: &inventory.Platform{},
		Connections: []*inventory.Config{{
			Type:    "k8s",
			Options: map[string]string{shared.OPTION_MANIFEST: dir, plugin.GitUrlOptionKey: gitURL},
		}},
	}
	conn, err := manifest.NewConnection(1, asset, manifest.WithManifestFile(dir))
	require.NoError(t, err)
	return conn
}

func ids(t *testing.T, conn shared.Connection) (string, string) {
	t.Helper()
	assetID, err := conn.AssetId()
	require.NoError(t, err)
	baseID, err := conn.BasePlatformId()
	require.NoError(t, err)
	return assetID, baseID
}

func TestGitCloneIdsDoNotDependOnTheClonePath(t *testing.T) {
	const repo = "https://dev.azure.com/org/project/_git/repo"
	firstAsset, firstBase := ids(t, cloneOf(t, repo))
	secondAsset, secondBase := ids(t, cloneOf(t, repo))
	require.Equal(t, firstAsset, secondAsset, "a rescan of the same repository is the same asset")
	require.Equal(t, firstBase, secondBase, "the repository's namespaces and workloads keep their ids")

	// A trailing .git names the same repository.
	gitAsset, _ := ids(t, cloneOf(t, repo+".git"))
	require.Equal(t, firstAsset, gitAsset)

	otherAsset, _ := ids(t, cloneOf(t, "https://dev.azure.com/org/project/_git/other"))
	require.NotEqual(t, firstAsset, otherAsset, "another repository is another asset")
}
