// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/stretchr/testify/assert"
)

func TestDbaasApplyDetail(t *testing.T) {
	r := &mqlExoscaleDbaasService{}
	r.applyDetail(&dbaasDetail{
		version:     strPtr("16"),
		ipFilter:    []string{"0.0.0.0/0"},
		maintenance: &v3.DBAASServiceMaintenance{Dow: "sunday", Time: "02:00:00"},
	})
	assert.Equal(t, "16", r.Version.Data)
	assert.Equal(t, []any{"0.0.0.0/0"}, r.IpFilter.Data)
	assert.Equal(t, "sunday", r.MaintenanceDow.Data)
	assert.Equal(t, "02:00:00", r.MaintenanceTime.Data)
	assert.False(t, r.Version.IsNull())
}

func TestDbaasApplyDetailAbsentValues(t *testing.T) {
	// Thanos has no version; an empty ip filter is an answer (no access), not
	// a missing one.
	r := &mqlExoscaleDbaasService{}
	r.applyDetail(&dbaasDetail{ipFilter: nil})
	assert.True(t, r.Version.IsNull())
	assert.False(t, r.IpFilter.IsNull())
	assert.Equal(t, []any{}, r.IpFilter.Data)
	assert.True(t, r.MaintenanceDow.IsNull())

	// An engine the provider does not know leaves everything null.
	r = &mqlExoscaleDbaasService{}
	r.applyDetail(nil)
	assert.True(t, r.IpFilter.IsNull())
	assert.True(t, r.Version.IsNull())
}

func strPtr(s string) *string { return &s }
