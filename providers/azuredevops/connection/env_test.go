// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

func TestEnvironmentsAreReadOncePerProject(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	for range 3 {
		envs, err := c.Environments(context.Background(), "legacy-apps")
		require.NoError(t, err)
		require.Len(t, envs, 3)
		assert.Equal(t, Environment{ID: 1, Name: "production", Description: "Production deployments"}, envs[0])
	}
	reqs := srv.Requests()
	require.Len(t, reqs, 1)
	assert.Contains(t, reqs[0], "/legacy-apps/_apis/distributedtask/environments?")
	assert.Contains(t, reqs[0], "api-version="+PreviewAPIVersion)
}

func TestEnvironmentChecksAskForTheirSettings(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	checks, err := c.EnvironmentChecks(context.Background(), "legacy-apps", 1)
	require.NoError(t, err)
	require.Len(t, checks, 2)

	approval := checks[0]
	assert.Equal(t, int64(11), approval.ID)
	assert.True(t, strings.EqualFold(CheckTypeApproval, approval.Type.ID))
	assert.Equal(t, "Approval", approval.Type.Name)
	assert.False(t, approval.RequesterCannotBeApprover())
	assert.Equal(t, int64(1), approval.MinRequiredApprovers())
	assert.Equal(t, "Task Check", checks[1].Type.Name)

	reqs := srv.Requests()
	require.Len(t, reqs, 1)
	assert.Contains(t, reqs[0], "resourceType=environment")
	assert.Contains(t, reqs[0], "resourceId=1")
	assert.Contains(t, reqs[0], "%24expand=settings")
}

func TestEnvironmentChecksAreReadOncePerEnvironment(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	for _, id := range []int64{1, 2, 1, 2, 3} {
		_, err := c.EnvironmentChecks(context.Background(), "legacy-apps", id)
		require.NoError(t, err)
	}
	assert.Len(t, srv.Requests(), 3)
}

func TestCheckSettingsOfAnotherType(t *testing.T) {
	c := CheckConfiguration{Settings: map[string]any{"displayName": "Business hours"}}
	assert.False(t, c.RequesterCannotBeApprover())
	assert.Zero(t, c.MinRequiredApprovers())
	assert.False(t, CheckConfiguration{}.RequesterCannotBeApprover(), "no settings at all")
}

// Azure DevOps stores minRequiredApprovers 0 for "every approver must approve",
// the default. Reporting 0 would fail a policy that asks for one approval.
func TestMinRequiredApproversZeroMeansEveryApprover(t *testing.T) {
	two := []any{map[string]any{"id": "a"}, map[string]any{"id": "b"}}
	all := CheckConfiguration{Settings: map[string]any{"minRequiredApprovers": float64(0), "approvers": two}}
	assert.Equal(t, int64(2), all.MinRequiredApprovers())

	some := CheckConfiguration{Settings: map[string]any{"minRequiredApprovers": float64(1), "approvers": two}}
	assert.Equal(t, int64(1), some.MinRequiredApprovers())
}
