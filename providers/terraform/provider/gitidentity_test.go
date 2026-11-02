// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/utils/urlx"
)

func TestParseGitRemote(t *testing.T) {
	tests := []struct {
		url               string
		domain, org, repo string
	}{
		{"https://github.com/exampleorg/example-repo.git", "github.com", "exampleorg", "example-repo"},
		{"https://github.com/exampleorg/example-repo", "github.com", "exampleorg", "example-repo"},
		{"https://github.com/exampleorg/example-repo.git/", "github.com", "exampleorg", "example-repo"},
		// a CI token in the URL is not part of the identity
		{"https://gitlab-ci-token:s3cret@gitlab.example.com/exampleorg/example-repo.git", "gitlab.example.com", "exampleorg", "example-repo"},
		{"ssh://git@github.com:22/exampleorg/example-repo.git", "github.com", "exampleorg", "example-repo"},
		{"git://github.com/exampleorg/example-repo.git", "github.com", "exampleorg", "example-repo"},
		{"git@github.com:exampleorg/example-repo.git", "github.com", "exampleorg", "example-repo"},
		// middle segments are cut the way the ssh-url branch cuts them
		{"https://gitlab.example.com/exampleorg/group/example-repo.git", "gitlab.example.com", "exampleorg", "example-repo"},
		{"git@gitlab.example.com:exampleorg/group/example-repo.git", "gitlab.example.com", "exampleorg", "example-repo"},
		{"https://dev.azure.com/exampleorg/project/_git/example-repo", "dev.azure.com", "exampleorg", "example-repo"},
	}
	for _, tc := range tests {
		t.Run(tc.url, func(t *testing.T) {
			domain, org, repo, err := parseGitRemote(tc.url)
			require.NoError(t, err)
			assert.Equal(t, tc.domain, domain)
			assert.Equal(t, tc.org, org)
			assert.Equal(t, tc.repo, repo)
		})
	}

	// One repository, one identity, however its remote is spelled: the
	// scp-like form goes through urlx.ParseGitSshUrl, which the ssh-url
	// branch of detect() uses, and the URL forms must agree with it.
	t.Run("agrees with ParseGitSshUrl", func(t *testing.T) {
		sshDomain, sshOrg, sshRepo, err := urlx.ParseGitSshUrl("git@gitlab.example.com:exampleorg/group/example-repo.git")
		require.NoError(t, err)
		for _, spelled := range []string{
			"git@gitlab.example.com:exampleorg/group/example-repo.git",
			"https://gitlab.example.com/exampleorg/group/example-repo.git",
			"ssh://git@gitlab.example.com/exampleorg/group/example-repo.git",
		} {
			domain, org, repo, err := parseGitRemote(spelled)
			require.NoError(t, err, spelled)
			assert.Equal(t, []string{sshDomain, sshOrg, sshRepo}, []string{domain, org, repo}, spelled)
		}
	})

	for _, bad := range []string{"", "github.com", "/srv/git/example-repo.git", "https://github.com/", "https://github.com/onlyorg", "git@github.com:example-repo.git"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			_, _, _, err := parseGitRemote(bad)
			assert.Error(t, err)
		})
	}
}

// initCheckout creates a git repository at dir with the given origin URL and
// the sub-folders a scan would target.
func initCheckout(t *testing.T, dir, origin string, subdirs ...string) {
	t.Helper()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)
	if origin != "" {
		_, err = repo.CreateRemote(&config.RemoteConfig{Name: git.DefaultRemoteName, URLs: []string{origin}})
		require.NoError(t, err)
	}
	for _, sub := range subdirs {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o755))
	}
}

func TestDetectGitIdentity(t *testing.T) {
	t.Run("a sub-folder of a checkout carries the repository and its path", func(t *testing.T) {
		dir := t.TempDir()
		initCheckout(t, dir, "https://github.com/exampleorg/example-repo.git", "prod", "dev")

		gi, ok := detectGitIdentity(filepath.Join(dir, "prod"))
		require.True(t, ok)
		assert.Equal(t, gitIdentity{Domain: "github.com", Org: "exampleorg", Repo: "example-repo", RelPath: "prod"}, gi)
		assert.Equal(t, "//platformid.api.mondoo.app/runtime/terraform/domain/github.com/org/exampleorg/repo/example-repo/path/prod", gi.platformID())
		assert.Equal(t, "exampleorg/example-repo/prod", gi.name())

		dev, ok := detectGitIdentity(filepath.Join(dir, "dev"))
		require.True(t, ok)
		assert.NotEqual(t, gi.platformID(), dev.platformID(), "two folders of one repository are two assets")
	})

	t.Run("the repository root is the git-integration identity", func(t *testing.T) {
		dir := t.TempDir()
		initCheckout(t, dir, "git@github.com:exampleorg/example-repo.git")

		gi, ok := detectGitIdentity(dir)
		require.True(t, ok)
		assert.Equal(t, "", gi.RelPath)
		assert.Equal(t, "//platformid.api.mondoo.app/runtime/terraform/domain/github.com/org/exampleorg/repo/example-repo", gi.platformID())
		assert.Equal(t, "exampleorg/example-repo", gi.name())
	})

	t.Run("a file inside the checkout is identified by its path in the repository", func(t *testing.T) {
		dir := t.TempDir()
		initCheckout(t, dir, "https://github.com/exampleorg/example-repo.git", "plans")
		plan := filepath.Join(dir, "plans", "prod.json")
		require.NoError(t, os.WriteFile(plan, []byte("{}"), 0o644))

		gi, ok := detectGitIdentity(plan)
		require.True(t, ok)
		assert.Equal(t, "plans/prod.json", gi.RelPath)
	})

	t.Run("a checkout without a remote keeps the path hash", func(t *testing.T) {
		dir := t.TempDir()
		initCheckout(t, dir, "", "prod")

		_, ok := detectGitIdentity(filepath.Join(dir, "prod"))
		assert.False(t, ok)
	})

	t.Run("a directory outside any checkout keeps the path hash", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "prod"), 0o755))

		_, ok := detectGitIdentity(filepath.Join(dir, "prod"))
		assert.False(t, ok)
	})
}

// The bug this guards against: a CI template that checks every repository out
// into the same folder and scans its prod/ directory. With the path hash
// alone, both repositories below were one asset.
func TestDetect_TwoRepositoriesInOneWorkspace(t *testing.T) {
	workspace := t.TempDir()
	var ids, names []string
	for _, remote := range []string{"https://github.com/exampleorg/repo-a.git", "https://github.com/exampleorg/repo-b.git"} {
		require.NoError(t, os.RemoveAll(workspace))
		initCheckout(t, workspace, remote, "prod")

		asset := &inventory.Asset{Connections: []*inventory.Config{{
			Type:    HclConnectionType,
			Options: map[string]string{"path": filepath.Join(workspace, "prod")},
		}}}
		require.NoError(t, (&Service{}).detect(asset, nil))
		require.Len(t, asset.PlatformIds, 1)
		ids = append(ids, asset.PlatformIds[0])
		names = append(names, asset.Name)
		assert.Equal(t, asset.PlatformIds[0], asset.Connections[0].PlatformId)
	}
	assert.NotEqual(t, ids[0], ids[1], "the same workspace path holding two repositories is two assets")
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/terraform/domain/github.com/org/exampleorg/repo/repo-a/path/prod", ids[0])
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/terraform/domain/github.com/org/exampleorg/repo/repo-b/path/prod", ids[1])
	assert.Equal(t, []string{"Terraform HCL exampleorg/repo-a/prod", "Terraform HCL exampleorg/repo-b/prod"}, names)
}

// Every connection that scans by path, an HCL directory, a plan file or a
// state file, goes through the same branch of detect(), so all of them carry
// the repository identity inside a checkout.
func TestDetect_GitIdentityForEveryPathConnection(t *testing.T) {
	dir := t.TempDir()
	initCheckout(t, dir, "https://github.com/exampleorg/example-repo.git", "prod", "plans", "state")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "plans", "prod.json"), []byte("{}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "state", "prod.tfstate"), []byte("{}"), 0o644))

	tests := []struct {
		connType, path, id, name string
	}{
		{HclConnectionType, "prod", "/path/prod", "Terraform HCL exampleorg/example-repo/prod"},
		{PlanConnectionType, "plans/prod.json", "/path/plans/prod.json", "Terraform Plan exampleorg/example-repo/plans/prod.json"},
		{StateConnectionType, "state/prod.tfstate", "/path/state/prod.tfstate", "Terraform State exampleorg/example-repo/state/prod.tfstate"},
	}
	for _, tc := range tests {
		t.Run(tc.connType, func(t *testing.T) {
			asset := &inventory.Asset{Connections: []*inventory.Config{{
				Type:    tc.connType,
				Options: map[string]string{"path": filepath.Join(dir, filepath.FromSlash(tc.path))},
			}}}
			require.NoError(t, (&Service{}).detect(asset, nil))
			require.Len(t, asset.PlatformIds, 1)
			assert.Equal(t, "//platformid.api.mondoo.app/runtime/terraform/domain/github.com/org/exampleorg/repo/example-repo"+tc.id, asset.PlatformIds[0])
			assert.Equal(t, tc.name, asset.Name)
		})
	}
}

func TestDetect_PathOutsideGitKeepsHash(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "prod"), 0o755))
	asset := &inventory.Asset{Connections: []*inventory.Config{{
		Type:    HclConnectionType,
		Options: map[string]string{"path": filepath.Join(dir, "prod")},
	}}}
	require.NoError(t, (&Service{}).detect(asset, nil))
	require.Len(t, asset.PlatformIds, 1)
	assert.Contains(t, asset.PlatformIds[0], "//platformid.api.mondoo.app/runtime/terraform/hash/")
	assert.Equal(t, "Terraform HCL directory prod", asset.Name)
}
