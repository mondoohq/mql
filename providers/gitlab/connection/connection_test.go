// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func testConfig(options map[string]string, creds ...*vault.Credential) *inventory.Config {
	if options == nil {
		options = map[string]string{}
	}
	return &inventory.Config{Options: options, Credentials: creds}
}

func TestNewGitLabConnectionCredentials(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "")

	t.Run("token option is accepted", func(t *testing.T) {
		conn, err := NewGitLabConnection(1, &inventory.Asset{},
			testConfig(map[string]string{"token": "opt-token", "group": "acme"}))
		require.NoError(t, err)
		assert.True(t, conn.IsGroup())
		assert.False(t, conn.IsProject())
	})

	t.Run("env token is used when no option is set", func(t *testing.T) {
		t.Setenv("GITLAB_TOKEN", "env-token")
		_, err := NewGitLabConnection(1, &inventory.Asset{}, testConfig(map[string]string{"group": "acme"}))
		require.NoError(t, err)
	})

	t.Run("missing token is an error", func(t *testing.T) {
		_, err := NewGitLabConnection(1, &inventory.Asset{}, testConfig(nil))
		require.Error(t, err)
	})

	t.Run("password credential is used", func(t *testing.T) {
		_, err := NewGitLabConnection(1, &inventory.Asset{}, testConfig(
			map[string]string{"group": "acme"},
			&vault.Credential{Type: vault.CredentialType_password, Secret: []byte("cred-token")},
		))
		require.NoError(t, err)
	})

	t.Run("an unusable credential does not silently fall back to the env token", func(t *testing.T) {
		// Supplying a credential the provider cannot use previously left the
		// env/option token in place, so the scan ran as a different account
		// than the inventory asked for — with only a warning in the log.
		t.Setenv("GITLAB_TOKEN", "env-token")
		_, err := NewGitLabConnection(1, &inventory.Asset{}, testConfig(
			map[string]string{"group": "acme"},
			&vault.Credential{Type: vault.CredentialType_private_key, Secret: []byte("nope")},
		))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential")
	})
}

func TestGroupID(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "token")

	tests := []struct {
		name    string
		groupID string
		want    int64
	}{
		{"numeric id", "42", 42},
		{"unset", "", 0},
		{"non-numeric", "acme", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := NewGitLabConnection(1, &inventory.Asset{},
				testConfig(map[string]string{"group": "acme", "group-id": tt.groupID}))
			require.NoError(t, err)
			// GroupID swallows a parse failure and reports 0. Callers that
			// build asset platform ids must not rely on it — see
			// Service.detect, which resolves the real group instead.
			assert.Equal(t, tt.want, conn.GroupID())
		})
	}
}

func TestPID(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "token")

	t.Run("project-id wins", func(t *testing.T) {
		conn, err := NewGitLabConnection(1, &inventory.Asset{},
			testConfig(map[string]string{"group": "acme", "project": "api", "project-id": "77"}))
		require.NoError(t, err)
		pid, err := conn.PID()
		require.NoError(t, err)
		assert.Equal(t, "77", pid)
	})

	t.Run("falls back to group/project path", func(t *testing.T) {
		conn, err := NewGitLabConnection(1, &inventory.Asset{},
			testConfig(map[string]string{"group": "acme/platform", "project": "api"}))
		require.NoError(t, err)
		pid, err := conn.PID()
		require.NoError(t, err)
		assert.Equal(t, "acme/platform/api", pid)
	})

	t.Run("missing project is an error", func(t *testing.T) {
		conn, err := NewGitLabConnection(1, &inventory.Asset{},
			testConfig(map[string]string{"group": "acme"}))
		require.NoError(t, err)
		_, err = conn.PID()
		require.Error(t, err)
	})
}

func TestIsGroupIsProject(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "token")

	t.Run("project-id alone marks a project", func(t *testing.T) {
		conn, err := NewGitLabConnection(1, &inventory.Asset{},
			testConfig(map[string]string{"project-id": "77"}))
		require.NoError(t, err)
		assert.True(t, conn.IsProject())
		assert.False(t, conn.IsGroup())
	})

	t.Run("nested group path is still a group", func(t *testing.T) {
		conn, err := NewGitLabConnection(1, &inventory.Asset{},
			testConfig(map[string]string{"group": "acme/platform/api"}))
		require.NoError(t, err)
		assert.True(t, conn.IsGroup())
		assert.Equal(t, "acme/platform/api", conn.GroupName())
	})
}

func TestMemberRolesFetchesOncePerKey(t *testing.T) {
	// Synthetic: no target showed this.
	c := &GitLabConnection{}
	calls := map[string]int{}
	fetch := func(key string, roles []*gitlab.MemberRole, err error) func() ([]*gitlab.MemberRole, error) {
		return func() ([]*gitlab.MemberRole, error) {
			calls[key]++
			return roles, err
		}
	}

	groupRoles := []*gitlab.MemberRole{{ID: 7}}
	for range 3 {
		got, err := c.MemberRoles("group/acme", fetch("group/acme", groupRoles, nil))
		require.NoError(t, err)
		assert.Equal(t, groupRoles, got)
	}
	assert.Equal(t, 1, calls["group/acme"])

	refused := errors.New("403 Forbidden")
	for range 2 {
		got, err := c.MemberRoles("instance", fetch("instance", nil, refused))
		assert.Nil(t, got)
		assert.ErrorIs(t, err, refused)
	}
	assert.Equal(t, 1, calls["instance"], "a refused listing is remembered, not retried per grant")

	other, err := c.MemberRoles("group/other", fetch("group/other", nil, nil))
	require.NoError(t, err)
	assert.Empty(t, other)
	assert.Equal(t, 1, calls["group/other"])
}
