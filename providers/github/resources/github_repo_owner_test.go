// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestRepoOwner(t *testing.T) {
	owner := &mqlGithubUser{
		Login: plugin.TValue[string]{Data: "mondoohq", State: plugin.StateIsSet},
	}

	t.Run("owner present", func(t *testing.T) {
		repo := &mqlGithubRepository{
			Name:  plugin.TValue[string]{Data: "cnquery", State: plugin.StateIsSet},
			Owner: plugin.TValue[*mqlGithubUser]{Data: owner, State: plugin.StateIsSet},
		}

		got, err := repoOwner(repo)
		require.NoError(t, err)
		assert.Equal(t, owner, got)

		ownerLogin, repoName, err := repoOwnerAndName(repo)
		require.NoError(t, err)
		assert.Equal(t, "mondoohq", ownerLogin)
		assert.Equal(t, "cnquery", repoName)
	})

	// newMqlGithubRepository stores a null owner for repositories the API
	// returned without one. Reading Owner.Data directly used to panic here.
	t.Run("owner explicitly null", func(t *testing.T) {
		repo := &mqlGithubRepository{
			Name:  plugin.TValue[string]{Data: "cnquery", State: plugin.StateIsSet},
			Owner: plugin.TValue[*mqlGithubUser]{State: plugin.StateIsSet | plugin.StateIsNull},
		}

		_, err := repoOwner(repo)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cnquery")

		_, _, err = repoOwnerAndName(repo)
		require.Error(t, err)
	})

	// reposToMql builds repositories from a partial response, which leaves the
	// owner unset rather than null.
	t.Run("owner never set", func(t *testing.T) {
		repo := &mqlGithubRepository{
			Name: plugin.TValue[string]{Data: "cnquery", State: plugin.StateIsSet},
		}

		_, err := repoOwner(repo)
		require.Error(t, err)
	})

	t.Run("owner carries an error", func(t *testing.T) {
		boom := errors.New("boom")
		repo := &mqlGithubRepository{
			Name:  plugin.TValue[string]{Data: "cnquery", State: plugin.StateIsSet},
			Owner: plugin.TValue[*mqlGithubUser]{Error: boom, State: plugin.StateIsSet},
		}

		_, err := repoOwner(repo)
		assert.Equal(t, boom, err)
	})
}

func TestMergeRequestRepo(t *testing.T) {
	// owner is the pull request's author; repoOwnerLogin is the account that
	// holds the repository. Only the latter addresses the API correctly.
	t.Run("uses the repository owner", func(t *testing.T) {
		mr := &mqlGithubMergeRequest{
			RepoName:       plugin.TValue[string]{Data: "cnquery", State: plugin.StateIsSet},
			RepoOwnerLogin: plugin.TValue[string]{Data: "mondoohq", State: plugin.StateIsSet},
			Owner: plugin.TValue[*mqlGithubUser]{
				Data:  &mqlGithubUser{Login: plugin.TValue[string]{Data: "some-contributor", State: plugin.StateIsSet}},
				State: plugin.StateIsSet,
			},
		}

		ownerLogin, repoName, err := mergeRequestRepo(mr)
		require.NoError(t, err)
		assert.Equal(t, "mondoohq", ownerLogin)
		assert.Equal(t, "cnquery", repoName)
	})

	t.Run("missing repository owner errors", func(t *testing.T) {
		mr := &mqlGithubMergeRequest{
			RepoName: plugin.TValue[string]{Data: "cnquery", State: plugin.StateIsSet},
		}

		_, _, err := mergeRequestRepo(mr)
		require.Error(t, err)
	})
}

func TestIsBinaryFile(t *testing.T) {
	tests := []struct {
		fileType string
		path     string
		want     bool
	}{
		{"file", "app.exe", true},
		{"file", "tools/app.exe", true},
		// Regression: splitting the whole path on "." classified anything under
		// a dotted directory as non-binary.
		{"file", "v1.2/tool.exe", true},
		{"file", ".github/helper.exe", true},
		{"file", "dist/lib.so", true},
		{"file", "README.md", false},
		{"file", "Makefile", false},
		{"file", "archive.tar.gz", false},
		// Directories are never binaries, whatever they are named.
		{"dir", "vendor.exe", false},
		{"", "app.exe", false},
	}

	for _, tt := range tests {
		t.Run(tt.path+"/"+tt.fileType, func(t *testing.T) {
			assert.Equal(t, tt.want, isBinaryFile(tt.fileType, tt.path))
		})
	}
}
