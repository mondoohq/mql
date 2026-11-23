// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/google/go-github/v93/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Synthetic: status codes GitHub documents for the Actions permission
// endpoints; no target showed these.
func TestClassifyActionsSettingErr(t *testing.T) {
	unknown := []int{403, 404, 409, 422}
	for _, status := range unknown {
		assert.NoError(t, classifyActionsSettingErr(ghErrorResponse(status), "x", "org"),
			"status %d leaves the setting unknown", status)
	}

	assert.Error(t, classifyActionsSettingErr(ghErrorResponse(500), "x", "org"))
	assert.Error(t, classifyActionsSettingErr(errors.New("connection reset"), "x", "org"),
		"a transport failure must not turn into a null setting")
}

// Synthetic: the cache reads an endpoint once and keeps a refusal as unknown.
func TestActionsSettingGet(t *testing.T) {
	t.Run("fetches once", func(t *testing.T) {
		var c actionsSetting[github.ArtifactPeriod]
		calls := 0
		days := 90
		fetch := func() (*github.ArtifactPeriod, error) {
			calls++
			return &github.ArtifactPeriod{Days: &days}, nil
		}
		for range 3 {
			v, err := c.get("retention", "org", fetch)
			require.NoError(t, err)
			require.NotNil(t, v)
			assert.Equal(t, 90, *v.Days)
		}
		assert.Equal(t, 1, calls)
	})

	t.Run("refusal is unknown, not an error", func(t *testing.T) {
		var c actionsSetting[github.ArtifactPeriod]
		v, err := c.get("retention", "org", func() (*github.ArtifactPeriod, error) {
			return nil, ghErrorResponse(403)
		})
		assert.NoError(t, err)
		assert.Nil(t, v)
	})

	t.Run("server error stays an error", func(t *testing.T) {
		var c actionsSetting[github.ArtifactPeriod]
		_, err := c.get("retention", "org", func() (*github.ArtifactPeriod, error) {
			return nil, ghErrorResponse(502)
		})
		assert.Error(t, err)
	})
}

// Synthetic: fork pull request switches GitHub omitted, or a settings read
// that returned nothing, read null rather than false.
func TestForkPrBool(t *testing.T) {
	off, on := false, true
	p := &github.WorkflowsPermissions{
		RunWorkflowsFromForkPullRequests: &on,
		SendWriteTokensToWorkflows:       &off,
	}

	var field plugin.TValue[bool]
	v, err := forkPrBool(p, pickRunWorkflows, &field)
	require.NoError(t, err)
	assert.True(t, v)
	assert.False(t, field.IsNull())

	field = plugin.TValue[bool]{}
	v, err = forkPrBool(p, pickWriteTokens, &field)
	require.NoError(t, err)
	assert.False(t, v)
	assert.False(t, field.IsNull(), "an explicit false is a reading, not an absence")

	field = plugin.TValue[bool]{}
	_, err = forkPrBool(p, pickSecrets, &field)
	require.NoError(t, err)
	assert.True(t, field.IsNull(), "a switch GitHub did not report is null")

	field = plugin.TValue[bool]{}
	_, err = forkPrBool(nil, pickRequireApproval, &field)
	require.NoError(t, err)
	assert.True(t, field.IsNull(), "an unreadable setting is null")
}

// Synthetic: absent and empty values read null.
func TestOptionalStringAndInt(t *testing.T) {
	var s plugin.TValue[string]
	_, _ = optionalString(approvalPolicy(nil), &s)
	assert.True(t, s.IsNull())

	s = plugin.TValue[string]{}
	got, _ := optionalString(approvalPolicy(&github.ContributorApprovalPermissions{ApprovalPolicy: "first_time_contributors"}), &s)
	assert.Equal(t, "first_time_contributors", got)
	assert.False(t, s.IsNull())

	s = plugin.TValue[string]{}
	_, _ = optionalString(approvalPolicy(&github.ContributorApprovalPermissions{}), &s)
	assert.True(t, s.IsNull(), "an empty policy is no policy reported")

	var n plugin.TValue[int64]
	_, _ = optionalInt(retentionMaxDays(nil), &n)
	assert.True(t, n.IsNull())

	n = plugin.TValue[int64]{}
	days, maxDays := 30, 400
	period := &github.ArtifactPeriod{Days: &days, MaximumAllowedDays: &maxDays}
	got64, _ := optionalInt(retentionDays(period), &n)
	assert.Equal(t, int64(30), got64)
	got64, _ = optionalInt(retentionMaxDays(period), &n)
	assert.Equal(t, int64(400), got64)
	assert.False(t, n.IsNull())
}
