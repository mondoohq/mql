// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azuredevops/connection"
)

func projectNamed(t *testing.T, runtime *plugin.Runtime, name string) *mqlAzuredevopsProject {
	t.Helper()
	list := newOrganization(t, runtime).GetProjects()
	require.NoError(t, list.Error)
	for _, p := range list.Data {
		if project := p.(*mqlAzuredevopsProject); project.Name.Data == name {
			return project
		}
	}
	t.Fatalf("no project %q", name)
	return nil
}

func environmentsOf(t *testing.T, project *mqlAzuredevopsProject) map[string]*mqlAzuredevopsEnvironment {
	t.Helper()
	list := project.GetEnvironments()
	require.NoError(t, list.Error)
	require.False(t, list.IsNull())
	out := map[string]*mqlAzuredevopsEnvironment{}
	for _, x := range list.Data {
		env := x.(*mqlAzuredevopsEnvironment)
		out[env.Name.Data] = env
	}
	return out
}

func checksOf(t *testing.T, env *mqlAzuredevopsEnvironment) []*mqlAzuredevopsEnvironmentProtectionRule {
	t.Helper()
	list := env.GetProtectionRules()
	require.NoError(t, list.Error)
	require.False(t, list.IsNull())
	out := make([]*mqlAzuredevopsEnvironmentProtectionRule, 0, len(list.Data))
	for _, x := range list.Data {
		out = append(out, x.(*mqlAzuredevopsEnvironmentProtectionRule))
	}
	return out
}

func TestTheScanTestProjectHasNoEnvironments(t *testing.T) {
	envs := environmentsOf(t, projectNamed(t, newRuntime(t, nil), "scan-test"))
	assert.Empty(t, envs, "a project with no environments passes the environment check")
}

func TestEnvironmentApprovalsAndTheirSelfReviewSetting(t *testing.T) {
	envs := environmentsOf(t, projectNamed(t, newRuntime(t, nil), "legacy-apps"))
	require.Len(t, envs, 3)
	assert.Equal(t, int64(1), envs["production"].Id.Data)
	assert.Equal(t, "Production deployments", envs["production"].Description.Data)

	production := checksOf(t, envs["production"])
	require.Len(t, production, 2)
	approval, task := production[0], production[1]
	assert.Equal(t, "Approval", approval.Type.Data)
	assert.Equal(t, connection.CheckTypeApproval, approval.TypeId.Data, "the type id is in lower case")
	assert.False(t, approval.PreventSelfReview.Data, "the requester may approve production")
	assert.Equal(t, int64(1), approval.MinRequiredApprovers.Data)
	assert.Contains(t, approval.Settings.Data, "approvers")
	assert.Equal(t, "Task Check", task.Type.Data)
	assert.False(t, task.PreventSelfReview.Data)

	staging := checksOf(t, envs["staging"])
	require.Len(t, staging, 1)
	assert.True(t, staging[0].PreventSelfReview.Data)
	assert.Equal(t, int64(2), staging[0].MinRequiredApprovers.Data)

	assert.Empty(t, checksOf(t, envs["sandbox"]), "an environment with no checks has an empty list")
}

func TestEnvironmentsTheCredentialCannotReadAreForbidden(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.Deny("/_apis/distributedtask/environments")

	list := projectNamed(t, runtime, "legacy-apps").GetEnvironments()
	assert.ErrorIs(t, list.Error, llx.ErrForbidden)
}

func TestEnvironmentChecksTheCredentialCannotReadAreForbidden(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.Deny("/_apis/pipelines/checks/configurations")
	envs := environmentsOf(t, projectNamed(t, runtime, "legacy-apps"))

	list := envs["production"].GetProtectionRules()
	assert.ErrorIs(t, list.Error, llx.ErrForbidden)
}
