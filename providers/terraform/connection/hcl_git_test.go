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

// cloneConnection parses a directory the way NewHclGitConnection parses its
// clone, without a git server: the clone is a directory like any other.
func cloneConnection(t *testing.T) (*Connection, string) {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`resource "aws_s3_bucket" "b" {}`), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "infra", "my modules"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "infra", "my modules", "net.tf"), []byte(`resource "aws_vpc" "v" {}`), 0o644))

	asset := &inventory.Asset{Connections: []*inventory.Config{{Options: map[string]string{"path": root}}}}
	conn, err := newHclConnection(1, root, asset)
	require.NoError(t, err)
	conn.cloneRoot = root
	return conn, root
}

func TestRepositoryPath(t *testing.T) {
	conn, root := cloneConnection(t)
	files := conn.Parser().Files()
	require.Len(t, files, 2)

	t.Run("a parsed file is reported by its path in the repository", func(t *testing.T) {
		var got []string
		for name := range files {
			got = append(got, conn.RepositoryPath(name))
		}
		assert.ElementsMatch(t, []string{"main.tf", "infra/my modules/net.tf"}, got)
	})

	t.Run("the repository path finds the parsed file again", func(t *testing.T) {
		for name, file := range files {
			assert.Same(t, file, files[conn.SourcePath(conn.RepositoryPath(name))], name)
		}
	})

	t.Run("a path outside the clone is kept", func(t *testing.T) {
		outside := filepath.Join(filepath.Dir(root), "elsewhere", "main.tf")
		assert.Equal(t, outside, conn.RepositoryPath(outside))
		assert.Equal(t, root, conn.RepositoryPath(root), "the clone itself")
		assert.Equal(t, outside, conn.SourcePath(outside), "an absolute path is already on disk")
	})

	t.Run("a connection to a path the user gave keeps every path", func(t *testing.T) {
		local := &Connection{}
		path := filepath.Join(root, "main.tf")
		assert.Equal(t, path, local.RepositoryPath(path))
		assert.Equal(t, "main.tf", local.SourcePath("main.tf"))
	})
}

func TestLabelGitURL(t *testing.T) {
	gitAsset := func(gitURL string, labels map[string]string) *inventory.Asset {
		opts := map[string]string{"http-url": gitURL}
		if gitURL != "" {
			opts[plugin.GitUrlOptionKey] = gitURL
		}
		return &inventory.Asset{Labels: labels, Connections: []*inventory.Config{{Options: opts}}}
	}

	t.Run("the cloned repository, without .git", func(t *testing.T) {
		asset := gitAsset("https://dev.azure.com/org/my%20project/_git/infra.git", nil)
		labelGitURL(asset)
		assert.Equal(t, map[string]string{plugin.GitUrlOptionKey: "https://dev.azure.com/org/my%20project/_git/infra"}, asset.Labels)
	})

	t.Run("other labels are kept", func(t *testing.T) {
		asset := gitAsset("https://github.com/org/infra", map[string]string{"team": "platform"})
		labelGitURL(asset)
		assert.Equal(t, map[string]string{"team": "platform", plugin.GitUrlOptionKey: "https://github.com/org/infra"}, asset.Labels)
	})

	t.Run("nothing without a clone URL", func(t *testing.T) {
		asset := gitAsset("", nil)
		labelGitURL(asset)
		assert.Nil(t, asset.Labels)
	})
}
