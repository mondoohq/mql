// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql/llx"
)

func memberRolesList(roles ...*gitlab.MemberRole) func() ([]*gitlab.MemberRole, error) {
	return func() ([]*gitlab.MemberRole, error) { return roles, nil }
}

func TestResolveMemberRole(t *testing.T) {
	// Synthetic: role ids and names; no target showed this.
	groupRoles := memberRolesList(
		&gitlab.MemberRole{ID: 7, Name: "Security reviewer"},
		nil,
		&gitlab.MemberRole{ID: 9, Name: "Release manager"},
	)
	instanceRoles := memberRolesList(&gitlab.MemberRole{ID: 42, Name: "Instance auditor"})

	t.Run("present in the group list", func(t *testing.T) {
		role, err := resolveMemberRole(9, groupRoles, instanceRoles)
		require.NoError(t, err)
		require.NotNil(t, role)
		assert.Equal(t, "Release manager", role.Name)
	})

	t.Run("falls back to the instance list", func(t *testing.T) {
		role, err := resolveMemberRole(42, groupRoles, instanceRoles)
		require.NoError(t, err)
		require.NotNil(t, role)
		assert.Equal(t, "Instance auditor", role.Name)
	})

	t.Run("absent id reads no list", func(t *testing.T) {
		called := false
		probe := func() ([]*gitlab.MemberRole, error) {
			called = true
			return nil, nil
		}
		role, err := resolveMemberRole(0, probe)
		require.NoError(t, err)
		assert.Nil(t, role)
		assert.False(t, called, "a grant without a custom role must not trigger a listing")
	})

	t.Run("id in no list is null", func(t *testing.T) {
		role, err := resolveMemberRole(1234, groupRoles, instanceRoles)
		require.NoError(t, err)
		assert.Nil(t, role)
	})

	t.Run("refused list is skipped when another list holds the role", func(t *testing.T) {
		refused := func() ([]*gitlab.MemberRole, error) { return nil, llx.Forbidden(errors.New("403")) }
		role, err := resolveMemberRole(42, refused, instanceRoles)
		require.NoError(t, err)
		require.NotNil(t, role)
		assert.EqualValues(t, 42, role.ID)
	})

	t.Run("refused list is an error when no list holds the role", func(t *testing.T) {
		refused := func() ([]*gitlab.MemberRole, error) { return nil, llx.Forbidden(errors.New("403")) }
		role, err := resolveMemberRole(1234, groupRoles, refused)
		assert.Nil(t, role)
		assert.ErrorIs(t, err, llx.ErrForbidden)
	})
}

func TestTopLevelNamespacePath(t *testing.T) {
	// Synthetic: path shapes GitLab returns for projects and groups.
	assert.Equal(t, "acme", topLevelNamespacePath("acme/platform/api"))
	assert.Equal(t, "acme", topLevelNamespacePath("acme/api"))
	assert.Equal(t, "acme", topLevelNamespacePath("acme"))
	assert.Equal(t, "acme", topLevelNamespacePath("/acme/api/"))
	assert.Equal(t, "", topLevelNamespacePath(""))
}

func TestClassifyMemberRolesError(t *testing.T) {
	// Synthetic: status codes GitLab documents for the member roles API.
	status := func(code int) error {
		return &gitlab.ErrorResponse{StatusCode: code, Response: &http.Response{StatusCode: code}}
	}

	assert.NoError(t, classifyMemberRolesError(nil, "instance"))
	assert.NoError(t, classifyMemberRolesError(status(404), "instance"), "404 means no custom roles in this scope")
	assert.ErrorIs(t, classifyMemberRolesError(status(403), "instance"), llx.ErrForbidden)
	assert.ErrorIs(t, classifyMemberRolesError(status(401), "instance"), llx.ErrUnauthenticated)

	transport := errors.New("connection refused")
	err := classifyMemberRolesError(transport, "instance")
	assert.ErrorIs(t, err, transport)
	assert.NotErrorIs(t, err, llx.ErrForbidden, "a transport error is not a refusal")
}

func TestGitlabProjectArgsDuoSecuritySettings(t *testing.T) {
	decode := func(t *testing.T, payload string) map[string]*llx.RawData {
		t.Helper()
		prj := &gitlab.Project{}
		require.NoError(t, json.Unmarshal([]byte(payload), prj))
		return getGitlabProjectArgs(prj)
	}
	keys := []string{
		"duoSastFalsePositiveDetectionEnabled",
		"duoSastVulnerabilityResolutionEnabled",
		"duoSecretDetectionFalsePositiveDetectionEnabled",
	}

	// Synthetic: attribute names from the GitLab Projects API response; the
	// values differ per toggle so a swapped mapping fails. No target showed this.
	t.Run("each toggle maps to its own field", func(t *testing.T) {
		args := decode(t, `{"id":1,"duo_sast_fp_detection_enabled":true,"duo_sast_vr_workflow_enabled":false,"duo_secret_detection_fp_enabled":true}`)
		assert.Equal(t, true, args["duoSastFalsePositiveDetectionEnabled"].Value)
		assert.Equal(t, false, args["duoSastVulnerabilityResolutionEnabled"].Value)
		assert.Equal(t, true, args["duoSecretDetectionFalsePositiveDetectionEnabled"].Value)

		args = decode(t, `{"id":1,"duo_sast_fp_detection_enabled":false,"duo_sast_vr_workflow_enabled":true,"duo_secret_detection_fp_enabled":false}`)
		assert.Equal(t, false, args["duoSastFalsePositiveDetectionEnabled"].Value)
		assert.Equal(t, true, args["duoSastVulnerabilityResolutionEnabled"].Value)
		assert.Equal(t, false, args["duoSecretDetectionFalsePositiveDetectionEnabled"].Value)
	})

	// Synthetic: GitLab omits the attributes when the license lacks GitLab Duo
	// features; they must read false, not null. No target showed this.
	t.Run("omitted attributes read false", func(t *testing.T) {
		args := decode(t, `{"id":1}`)
		for _, k := range keys {
			require.Contains(t, args, k)
			assert.Equal(t, false, args[k].Value, k)
		}
	})
}
