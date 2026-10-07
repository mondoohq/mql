// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
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
	assert.False(t, task.PreventSelfReview.Data, "a check that is not an approval never prevents self-review, even when its settings say requesterCannotBeApprover")

	staging := checksOf(t, envs["staging"])
	require.Len(t, staging, 1)
	assert.True(t, staging[0].PreventSelfReview.Data)
	assert.Equal(t, int64(2), staging[0].MinRequiredApprovers.Data)

	assert.Empty(t, checksOf(t, envs["sandbox"]), "an environment with no checks has an empty list")
}

// The Task Check of the production environment carries minRequiredApprovers in
// its settings. A check that is not an approval needs no approvers, so the typed
// field is zero whatever the settings say, and the settings dict keeps the key.
func TestOnlyAnApprovalReportsMinRequiredApprovers(t *testing.T) {
	envs := environmentsOf(t, projectNamed(t, newRuntime(t, nil), "legacy-apps"))
	production := checksOf(t, envs["production"])
	require.Len(t, production, 2)
	approval, task := production[0], production[1]
	require.Equal(t, "Task Check", task.Type.Data)

	settings, ok := task.Settings.Data.(map[string]any)
	require.True(t, ok, "the settings are a dict")
	assert.EqualValues(t, 2, settings["minRequiredApprovers"], "the settings dict keeps the key")
	assert.Zero(t, task.MinRequiredApprovers.Data, "a check that is not an approval gives 0, even when its settings say minRequiredApprovers")
	assert.Equal(t, int64(1), approval.MinRequiredApprovers.Data, "an approval reports its own count")
}

// A check type can carry a secret in its settings, such as the key of a function
// check. The settings dict keeps only the keys that carry none.
func TestEnvironmentCheckSettingsCarryNoSecret(t *testing.T) {
	envs := environmentsOf(t, projectNamed(t, newRuntime(t, nil), "legacy-apps"))
	production := checksOf(t, envs["production"])
	require.Len(t, production, 2)
	approval, task := production[0], production[1]

	assert.Contains(t, task.Settings.Data, "displayName")
	assert.Contains(t, task.Settings.Data, "definitionRef")
	assert.NotContains(t, task.Settings.Data, "inputs", "the inputs of a check can hold a function key, an address code, headers or a body")
	assert.Contains(t, approval.Settings.Data, "approvers")

	for _, check := range []*mqlAzuredevopsEnvironmentProtectionRule{approval, task} {
		raw, err := json.Marshal(check.Settings.Data)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), "fabricated-function-key-0001", check.Type.Data)
	}
}

func TestCheckSettingsKeepsOnlyTheAllowedKeys(t *testing.T) {
	in := map[string]any{
		"instructions": "Check the change record",
		"inputs":       map[string]any{"key": "fabricated-function-key-0001"},
		"urlSuffix":    "/gate?code=fabricated-function-key-0001",
		"unknown":      true,
	}
	out := checkSettings(in)
	assert.Equal(t, map[string]any{"instructions": "Check the change record"}, out)
	assert.Len(t, in, 4, "the input is not changed")

	for name, raw := range map[string]map[string]any{"nil": nil, "empty": {}} {
		out := checkSettings(raw)
		assert.NotNil(t, out, name)
		assert.Empty(t, out, name)
	}
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
