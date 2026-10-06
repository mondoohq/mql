// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/stretchr/testify/require"
	inventory "go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// isolateTempDir points os.TempDir at a fresh directory and returns it, so a
// test can see exactly which clone directories gitClone created and left.
func isolateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	return dir
}

func cloneDirsIn(t *testing.T, tmp string) []string {
	t.Helper()
	entries, err := os.ReadDir(tmp)
	require.NoError(t, err)
	var dirs []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "mql-git-clone") {
			dirs = append(dirs, e.Name())
		}
	}
	return dirs
}

func TestGitClone_ReturnsTheRepositoryAndACloserThatRemovesIt(t *testing.T) {
	tmp := isolateTempDir(t)
	srv := newFakeGitServer(t, fakeStandard, fixtureToken)

	dir, closer, err := gitClone(srv.repoURL("localhost", "ci:"+fixtureToken))
	require.NoError(t, err)
	require.NotNil(t, closer)

	got, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	require.Equal(t, fixtureMainTF, string(got))
	require.Len(t, cloneDirsIn(t, tmp), 1)

	closer()
	require.Empty(t, cloneDirsIn(t, tmp))
}

// A failed clone used to come back as ("", nil, nil): the deferred cleanup
// assigned the function's shared err, which wiped the real one. Callers then
// carried on with an empty path. These tests pin the error and the cleanup.
func TestGitClone_AuthenticationFailureIsReturnedAsAnError(t *testing.T) {
	tmp := isolateTempDir(t)
	srv := newFakeGitServer(t, fakeStandard, fixtureToken)

	dir, closer, err := gitClone(srv.repoURL("localhost", "ci:not-the-token"))

	require.Error(t, err)
	require.ErrorContains(t, err, "failed to clone git repo")
	require.ErrorIs(t, err, transport.ErrAuthenticationRequired)
	require.Empty(t, dir)
	require.Nil(t, closer)
	require.Empty(t, cloneDirsIn(t, tmp), "a failed clone must not leave its temp dir behind")
}

func TestGitClone_EmptyRepositoryIsReturnedAsAnError(t *testing.T) {
	tmp := isolateTempDir(t)
	srv := newEmptyFakeGitServer(t, fakeStandard, fixtureToken)

	dir, closer, err := gitClone(srv.repoURL("localhost", "ci:"+fixtureToken))

	require.Error(t, err)
	require.ErrorContains(t, err, "remote repository is empty")
	require.Empty(t, dir)
	require.Nil(t, closer)
	require.Empty(t, cloneDirsIn(t, tmp))
}

func gitAsset(httpURL string, creds ...*vault.Credential) *inventory.Asset {
	return &inventory.Asset{
		Name: "fixture",
		Connections: []*inventory.Config{{
			Options:     map[string]string{"http-url": httpURL},
			Credentials: creds,
		}},
	}
}

func passwordCred(user, secret, password string) *vault.Credential {
	c := &vault.Credential{Type: vault.CredentialType_password, User: user, Password: password}
	if secret != "" {
		c.Secret = []byte(secret)
	}
	return c
}

func TestNewGitClone_BadCredentialsReturnAnErrorAndNoPath(t *testing.T) {
	isolateTempDir(t)
	srv := newFakeGitServer(t, fakeStandard, fixtureToken)

	path, closer, err := NewGitClone(gitAsset(srv.repoURL("localhost", ""), passwordCred("ci", "wrong-token", "")))

	require.Error(t, err)
	require.ErrorContains(t, err, "failed to clone git repo")
	require.Empty(t, path)
	require.Nil(t, closer)
	require.NotContains(t, err.Error(), "wrong-token")
}

func TestNewGitClone_InputErrorsAreUnchanged(t *testing.T) {
	_, _, err := NewGitClone(&inventory.Asset{Connections: []*inventory.Config{{}}})
	require.EqualError(t, err, "missing URLs in options for HCL over Git connection")

	_, _, err = NewGitClone(&inventory.Asset{Name: "n", Connections: []*inventory.Config{{Options: map[string]string{"other": "x"}}}})
	require.EqualError(t, err, "missing url for git repo n")
}
