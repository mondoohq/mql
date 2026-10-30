// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

func TestAdvSecEnablementOfARepositoryThatWasNeverTurnedOn(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	e, err := c.AdvSecEnablement(context.Background(), "scan-test", fakeado.RepoIacID)
	require.NoError(t, err)
	assert.False(t, e.Enabled)
	assert.Nil(t, e.LastChanged(), "the year-one date means never")

	reqs := srv.Requests()
	require.Len(t, reqs, 1)
	assert.Contains(t, reqs[0], "/advsec/"+fakeado.Org+"/scan-test/_apis/management/repositories/"+fakeado.RepoIacID+"/enablement?")
	assert.Contains(t, reqs[0], "api-version="+AdvSecAPIVersion)
}

func TestAdvSecEnablementIsReadOncePerRepository(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))
	srv.EnableAdvancedSecurity(fakeado.RepoAppID)

	for range 3 {
		e, err := c.AdvSecEnablement(context.Background(), "scan-test", fakeado.RepoAppID)
		require.NoError(t, err)
		assert.True(t, e.Enabled)
		require.NotNil(t, e.LastChanged())
		assert.Equal(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), *e.LastChanged())
	}
	assert.Len(t, srv.Requests(), 1)
}

func TestAlertsOfARepositoryWithoutAdvancedSecurityAreDisabled(t *testing.T) {
	c, _, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	_, err := c.Alerts(context.Background(), "scan-test", fakeado.RepoAppID)
	require.Error(t, err)
	assert.True(t, IsAdvSecDisabled(err))
}

func TestAlertsListEveryAlert(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))
	srv.EnableAdvancedSecurity(fakeado.RepoAppID)

	alerts, err := c.Alerts(context.Background(), "scan-test", fakeado.RepoAppID)
	require.NoError(t, err)
	require.Len(t, alerts, 4)
	assert.Equal(t, Alert{
		ID: 1, AlertType: "secret", Severity: "critical", State: "active",
		Title: "Fabricated AWS access key", GitRef: "refs/heads/main", FirstSeenRaw: "2026-01-02T00:00:00Z",
	}, alerts[0])
	assert.Equal(t, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), *alerts[0].FirstSeen())
}

func TestParseDate(t *testing.T) {
	utc := func(y int, m time.Month, d, h int) *time.Time {
		t := time.Date(y, m, d, h, 0, 0, 0, time.UTC)
		return &t
	}
	tests := []struct {
		in   string
		want *time.Time
	}{
		{"2026-01-01T00:00:00Z", utc(2026, 1, 1, 0)},
		{"2026-01-01T02:00:00+02:00", utc(2026, 1, 1, 0)},
		{"2026-01-01T00:00:00.1234567Z", func() *time.Time { t := time.Date(2026, 1, 1, 0, 0, 0, 123456700, time.UTC); return &t }()},
		{"2026-01-01T05:00:00", utc(2026, 1, 1, 5)},
		{"0001-01-01T00:00:00", nil},
		{"0001-01-01T00:00:00Z", nil},
		{"", nil},
		{"yesterday", nil},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, parseDate(tc.in))
		})
	}
}
