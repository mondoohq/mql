// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// gitRepo commits files into a new repository and returns its file:// URL,
// which a terraform-hcl-git connection clones like any remote.
func gitRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)
	wt, err := repo.Worktree()
	require.NoError(t, err)
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		_, err = wt.Add(name)
		require.NoError(t, err)
	}
	_, err = wt.Commit("seed", &git.CommitOptions{Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}})
	require.NoError(t, err)
	return "file://" + dir
}

func TestHclGitConnection_RepositoryPaths(t *testing.T) {
	url := gitRepo(t, map[string]string{
		"main.tf":                 "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"b\"\n}\n",
		"infra/my modules/net.tf": "resource \"aws_vpc\" \"v\" {}\n",
	})

	// A platform, as the provider that discovered the repository sets it,
	// skips the detection that names the asset from a hosted repository URL.
	srv := &Service{Service: plugin.NewService()}
	connRes, err := srv.Connect(&plugin.ConnectReq{Asset: &inventory.Asset{
		Platform: &inventory.Platform{Name: "terraform-hcl"},
		Connections: []*inventory.Config{{
			Type:    HclGitConnectionType,
			Options: map[string]string{"http-url": url},
		}},
	}}, nil)
	require.NoError(t, err)

	field := func(resource, id, name string) *plugin.DataRes {
		t.Helper()
		res, err := srv.GetData(&plugin.DataReq{Connection: connRes.Id, Resource: resource, ResourceId: id, Field: name})
		require.NoError(t, err)
		require.Empty(t, res.Error)
		return res
	}
	tf, err := srv.GetData(&plugin.DataReq{Connection: connRes.Id, Resource: "terraform"})
	require.NoError(t, err)
	tfID := string(tf.Data.Value)

	t.Run("the asset is labelled with the cloned repository", func(t *testing.T) {
		assert.Equal(t, url, connRes.Asset.Labels[plugin.GitUrlOptionKey])
	})

	t.Run("files are reported by their path in the repository", func(t *testing.T) {
		var paths []string
		for _, f := range field("terraform", tfID, "files").Data.Array {
			id := string(f.Value)
			paths = append(paths, string(field("terraform.file", id, "path").Data.Value))
			assert.Len(t, field("terraform.file", id, "blocks").Data.Array, 1, "the repository path finds the file's blocks")
		}
		assert.ElementsMatch(t, []string{"main.tf", "infra/my modules/net.tf"}, paths)
	})

	t.Run("a block's position and context name the file in the repository", func(t *testing.T) {
		var starts, contexts []string
		for _, b := range field("terraform", tfID, "blocks").Data.Array {
			id := string(b.Value)
			start := string(field("terraform.block", id, "start").Data.Value)
			starts = append(starts, string(field("terraform.fileposition", start, "path").Data.Value))
			ctx := string(field("terraform.block", id, "context").Data.Value)
			contexts = append(contexts, string(field("terraform.context", ctx, "path").Data.Value))
		}
		assert.ElementsMatch(t, []string{"main.tf", "infra/my modules/net.tf"}, starts)
		assert.ElementsMatch(t, []string{"main.tf", "infra/my modules/net.tf"}, contexts)
	})
}
