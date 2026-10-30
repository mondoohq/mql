// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogpushJobs(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/logpush/jobs", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("logpush_jobs"))
	})

	result, err := zone.logpushJobs()
	require.NoError(t, err)
	require.Len(t, result, 1)

	job := result[0].(*mqlCloudflareZoneLogpushJob)
	// The cache key must embed the zone: id() reads a zoneID set only after
	// NewResource returns, so the fix passes __id explicitly. Without it the
	// key was `logpush@@42` (empty zone) and jobs with the same numeric id in
	// different zones would alias.
	assert.Contains(t, job.MqlID(), testZoneID, "logpush job __id must be zone-scoped")
	assert.Equal(t, int64(42), job.Id.Data)
	assert.Equal(t, "HTTP Requests to S3", job.Name.Data)
	assert.Equal(t, "http_requests", job.Dataset.Data)
	assert.True(t, job.Enabled.Data)
	assert.Equal(t, "high", job.Frequency.Data)
	assert.Equal(t, "s3://mybucket/logs?region=us-east-1", job.DestinationConf.Data)
	assert.Equal(t, "", job.ErrorMessage.Data)
	assert.False(t, job.LastComplete.Data.IsZero())
	assert.True(t, job.FilterAttackTraffic.Data)
}

// filter_attack_traffic is optional on the job payload. An absent value must
// stay null: false would claim attack traffic is known to be exported.
func TestLogpushJobsFilterAttackTraffic(t *testing.T) {
	for _, tc := range []struct {
		name     string
		field    string
		wantData bool
		wantNull bool
	}{
		{name: "enabled", field: `,"filter_attack_traffic":true`, wantData: true},
		{name: "disabled", field: `,"filter_attack_traffic":false`, wantData: false},
		{name: "absent", field: ``, wantNull: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := setupTestEnv(t)
			zone := createTestZone(t, env)

			env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/logpush/jobs", testZoneID), func(w http.ResponseWriter, r *http.Request) {
				jsonResponse(w, fmt.Sprintf(
					`{"success":true,"result":[{"id":7,"name":"fw","dataset":"firewall_events"%s}]}`,
					tc.field))
			})

			result, err := zone.logpushJobs()
			require.NoError(t, err)
			require.Len(t, result, 1)
			job := result[0].(*mqlCloudflareZoneLogpushJob)

			if tc.wantNull {
				assert.True(t, job.FilterAttackTraffic.IsNull(), "an absent setting must read as null, not as false")
				return
			}
			assert.False(t, job.FilterAttackTraffic.IsNull())
			assert.Equal(t, tc.wantData, job.FilterAttackTraffic.Data)
		})
	}
}
