// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

// alertRequests counts the alert requests the fake served.
func alertRequests(srv *fakeado.Server) int {
	n := 0
	for _, r := range srv.Requests() {
		if strings.Contains(r, "/alerts?") {
			n++
		}
	}
	return n
}

func TestAdvancedSecurityIsOffByDefaultAndItsAlertsAreNull(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoIacID]

	as := repo.GetAdvancedSecurity()
	require.NoError(t, as.Error)
	require.False(t, as.IsNull())
	assert.False(t, as.Data.Enabled.Data)
	assert.Nil(t, as.Data.EnablementLastChangedDate.Data, "never turned on")

	alerts := as.Data.GetAlerts()
	require.NoError(t, alerts.Error)
	assert.True(t, alerts.IsNull(), "a check of the alerts must not pass on a repository nothing scans")
	assert.Zero(t, alertRequests(srv), "no alert request when Advanced Security is off")
}

func TestAdvancedSecurityListsTheAlertsOfAnEnabledRepository(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.EnableAdvancedSecurity(fakeado.RepoAppID)
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoAppID]

	as := repo.GetAdvancedSecurity()
	require.NoError(t, as.Error)
	assert.True(t, as.Data.Enabled.Data)
	require.NotNil(t, as.Data.EnablementLastChangedDate.Data)
	assert.Equal(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), as.Data.EnablementLastChangedDate.Data.UTC())

	alerts := as.Data.GetAlerts()
	require.NoError(t, alerts.Error)
	require.Len(t, alerts.Data, 4)
	first := alerts.Data[0].(*mqlAzuredevopsAlert)
	assert.Equal(t, int64(1), first.Id.Data)
	assert.Equal(t, "secret", first.AlertType.Data)
	assert.Equal(t, "critical", first.Severity.Data)
	assert.Equal(t, "active", first.State.Data)
	assert.Equal(t, "refs/heads/main", first.GitRef.Data)
	assert.Equal(t, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), first.FirstSeenDate.Data.UTC())
}

func TestAnEnabledRepositoryWithNoAlertsHasAnEmptyList(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.EnableAdvancedSecurity(fakeado.RepoIacID)
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoIacID]

	alerts := repo.GetAdvancedSecurity().Data.GetAlerts()
	require.NoError(t, alerts.Error)
	assert.False(t, alerts.IsNull())
	assert.Empty(t, alerts.Data)
}

func TestAdvancedSecurityTheCredentialCannotReadIsForbidden(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.Deny("/enablement")
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoAppID]

	as := repo.GetAdvancedSecurity()
	assert.ErrorIs(t, as.Error, llx.ErrForbidden)
}

func TestAlertsTheCredentialCannotReadAreForbidden(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.EnableAdvancedSecurity(fakeado.RepoAppID)
	srv.Deny("/alerts")
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoAppID]

	as := repo.GetAdvancedSecurity()
	require.NoError(t, as.Error)
	assert.True(t, as.Data.Enabled.Data)
	alerts := as.Data.GetAlerts()
	assert.ErrorIs(t, alerts.Error, llx.ErrForbidden)
}

// Advanced Security answers 400 VS2150009 for a repository it is off for. The
// enablement route is read as off, not as an error, and the alerts stay null
// without a request.
func TestAnEnablementRouteThatAnswersNotEnabledReadsAsOff(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.AnswerAdvancedSecurityOff("/enablement")
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoAppID]

	as := repo.GetAdvancedSecurity()
	require.NoError(t, as.Error)
	require.False(t, as.IsNull())
	assert.False(t, as.Data.Enabled.Data)
	assert.Nil(t, as.Data.EnablementLastChangedDate.Data)

	alerts := as.Data.GetAlerts()
	require.NoError(t, alerts.Error)
	assert.True(t, alerts.IsNull(), "a check of the alerts must not pass on a repository nothing scans")
	assert.Zero(t, alertRequests(srv), "no alert request when Advanced Security is off")
}

// When the enablement route says on and the alert route then answers the same
// 400, the alerts are null, not an error and not an empty list.
func TestAnAlertRouteThatAnswersNotEnabledGivesNullAlerts(t *testing.T) {
	runtime, srv := newDiscoveryRuntime(t, nil, nil)
	srv.EnableAdvancedSecurity(fakeado.RepoAppID)
	srv.AnswerAdvancedSecurityOff("/alerts")
	repo := repositoriesOf(t, newOrganization(t, runtime))[fakeado.RepoAppID]

	as := repo.GetAdvancedSecurity()
	require.NoError(t, as.Error)
	assert.True(t, as.Data.Enabled.Data)

	alerts := as.Data.GetAlerts()
	require.NoError(t, alerts.Error)
	assert.True(t, alerts.IsNull())
	assert.Equal(t, 1, alertRequests(srv), "the alert route was asked once")
}
