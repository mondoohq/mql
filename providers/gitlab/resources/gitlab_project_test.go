// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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

func TestProjectCIPolicyDecodesHardeningSettings(t *testing.T) {
	// Synthetic: attribute names from the GitLab Projects API; booleans
	// alternate and numbers differ so a tag on the wrong field fails. No target
	// showed these values.
	ci := &projectCIPolicy{}
	require.NoError(t, json.Unmarshal([]byte(`{
		"ci_pipeline_variables_minimum_override_role": "maintainer",
		"ci_push_repository_for_job_token_allowed": true,
		"ci_separated_caches": false,
		"allow_pipeline_trigger_approve_deployment": true,
		"protect_merge_request_pipelines": false,
		"ci_forward_deployment_enabled": true,
		"ci_forward_deployment_rollback_allowed": false,
		"ci_restrict_pipeline_cancellation_role": "developer",
		"ci_display_pipeline_variables": true,
		"ci_config_path": "ci/main.yml@acme/pipelines",
		"keep_latest_artifact": false,
		"ci_delete_pipelines_in_seconds": 2592000,
		"build_timeout": 3600
	}`), ci))

	assert.Equal(t, "maintainer", *ci.PipelineVariablesMinimumOverrideRole)
	assert.True(t, *ci.PushRepositoryForJobTokenAllowed)
	assert.False(t, *ci.SeparatedCaches)
	assert.True(t, *ci.AllowPipelineTriggerApproveDeployment)
	assert.False(t, *ci.ProtectMergeRequestPipelines)
	assert.True(t, *ci.ForwardDeploymentEnabled)
	assert.False(t, *ci.ForwardDeploymentRollbackAllowed)
	assert.Equal(t, "developer", *ci.RestrictPipelineCancellationRole)
	assert.True(t, *ci.DisplayPipelineVariables)
	assert.Equal(t, "ci/main.yml@acme/pipelines", *ci.ciConfigPath())
	assert.False(t, *ci.KeepLatestArtifact)
	assert.EqualValues(t, 2592000, *ci.ciDeletePipelinesInSeconds())
	assert.EqualValues(t, 3600, *ci.BuildTimeout)
}

func TestProjectCIPolicyDefaultsAndWithheldSettings(t *testing.T) {
	// Synthetic: GitLab sends null for the default configuration path and for
	// "keep pipelines forever"; a token below Maintainer gets neither key.
	ci := &projectCIPolicy{}
	require.NoError(t, json.Unmarshal([]byte(`{"ci_config_path": null, "ci_delete_pipelines_in_seconds": null}`), ci))
	require.NotNil(t, ci.ciConfigPath())
	assert.Equal(t, "", *ci.ciConfigPath(), "an explicit null is the default .gitlab-ci.yml")
	require.NotNil(t, ci.ciDeletePipelinesInSeconds())
	assert.EqualValues(t, 0, *ci.ciDeletePipelinesInSeconds(), "an explicit null means pipelines are never deleted")

	withheld := &projectCIPolicy{}
	require.NoError(t, json.Unmarshal([]byte(`{"id": 7}`), withheld))
	assert.Nil(t, withheld.ciConfigPath(), "a withheld setting must read null, not the default path")
	assert.Nil(t, withheld.ciDeletePipelinesInSeconds())
	assert.Nil(t, withheld.SeparatedCaches)
	assert.Nil(t, withheld.BuildTimeout)
}

func TestProjectSettingsPolicyDecode(t *testing.T) {
	// Synthetic: attribute names from the GitLab Projects API. No target
	// showed these values.
	settings := &projectSettingsPolicy{}
	require.NoError(t, json.Unmarshal([]byte(`{
		"enforce_auth_checks_on_uploads": true,
		"only_allow_merge_if_all_status_checks_passed": false,
		"merge_trains_skip_train_allowed": true,
		"merge_train_enforcement": "enforced",
		"external_authorization_classification_label": "confidential",
		"mirror_user_id": 42,
		"mirror_overwrites_diverged_branches": false
	}`), settings))
	assert.True(t, *settings.EnforceAuthChecksOnUploads)
	assert.False(t, *settings.OnlyAllowMergeIfAllStatusChecksPassed)
	assert.True(t, *settings.MergeTrainsSkipTrainAllowed)
	assert.Equal(t, "enforced", *settings.MergeTrainEnforcement)
	assert.Equal(t, "confidential", *settings.ExternalAuthorizationClassificationLabel)
	assert.EqualValues(t, 42, *settings.MirrorUserID)
	assert.False(t, *settings.MirrorOverwritesDivergedBranches)
}

func TestGitlabProjectArgsFeatureAccessLevels(t *testing.T) {
	// Synthetic: each access level gets a different value so a swapped mapping
	// fails. No target showed these values.
	prj := &gitlab.Project{}
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": 1,
		"releases_access_level": "enabled",
		"pages_access_level": "public",
		"environments_access_level": "private",
		"package_registry_access_level": "disabled",
		"feature_flags_access_level": "enabled",
		"infrastructure_access_level": "private",
		"monitor_access_level": "disabled",
		"analytics_access_level": "public",
		"requirements_access_level": "private",
		"marked_for_deletion_on": "2026-12-01",
		"topics": ["payments", "pci"]
	}`), prj))
	args := getGitlabProjectArgs(prj)

	assert.Equal(t, "enabled", args["releasesAccessLevel"].Value)
	assert.Equal(t, "public", args["pagesAccessLevel"].Value)
	assert.Equal(t, "private", args["environmentsAccessLevel"].Value)
	assert.Equal(t, "disabled", args["packageRegistryAccessLevel"].Value)
	assert.Equal(t, "enabled", args["featureFlagsAccessLevel"].Value)
	assert.Equal(t, "private", args["infrastructureAccessLevel"].Value)
	assert.Equal(t, "disabled", args["monitorAccessLevel"].Value)
	assert.Equal(t, "public", args["analyticsAccessLevel"].Value)
	assert.Equal(t, "private", args["requirementsAccessLevel"].Value)
	assert.Equal(t, []any{"payments", "pci"}, args["topics"].Value)
	require.NotNil(t, args["markedForDeletionOn"].Value)
	assert.Equal(t, "2026-12-01", args["markedForDeletionOn"].Value.(*time.Time).Format("2006-01-02"))

	// Synthetic: a project not scheduled for deletion.
	args = getGitlabProjectArgs(&gitlab.Project{ID: 2})
	assert.Nil(t, args["markedForDeletionOn"].Value, "a project not scheduled for deletion must read null, not year 1")
}

func TestProjectCIFieldsFollowTheSharedPayload(t *testing.T) {
	newProject := func(t *testing.T, status int, body string) *mqlGitlabProject {
		t.Helper()
		runtime := newTestGroupRuntime(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v4/projects/7", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			fmt.Fprint(w, body)
		}))
		res, err := CreateResource(runtime, "gitlab.project", map[string]*llx.RawData{"id": llx.IntData(7)})
		require.NoError(t, err)
		return res.(*mqlGitlabProject)
	}

	// Synthetic: a Maintainer token reads the CI/CD settings and a pull mirror user.
	p := newProject(t, http.StatusOK, `{"id": 7, "ci_separated_caches": false, "build_timeout": 600, "mirror_user_id": 0}`)
	caches := p.GetCiSeparatedCaches()
	require.NoError(t, caches.Error)
	assert.False(t, caches.Data)
	assert.Zero(t, caches.State&plugin.StateIsNull, "a reported false must not read null")
	assert.EqualValues(t, 600, p.GetBuildTimeout().Data)
	assert.NotZero(t, p.GetKeepLatestArtifact().State&plugin.StateIsNull, "an attribute missing from the payload reads null")
	mirrorUser := p.GetMirrorUser()
	require.NoError(t, mirrorUser.Error)
	assert.NotZero(t, mirrorUser.State&plugin.StateIsNull, "mirror_user_id 0 means no pull mirror")

	// Synthetic: a token that cannot read the project at all.
	denied := newProject(t, http.StatusForbidden, `{"message": "403 Forbidden"}`)
	timeout := denied.GetBuildTimeout()
	require.NoError(t, timeout.Error)
	assert.NotZero(t, timeout.State&plugin.StateIsNull)
	enforced := denied.GetEnforceAuthChecksOnUploads()
	require.NoError(t, enforced.Error)
	assert.NotZero(t, enforced.State&plugin.StateIsNull)
}
