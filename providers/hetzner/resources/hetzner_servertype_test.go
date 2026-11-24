// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/stretchr/testify/assert"
)

// The type-wide schedule and the shipped `deprecated` bool read from the same
// embedded DeprecatableResource, so a type flagged deprecated must also report
// when it goes away. A fleet on a retiring type cannot be prioritized from the
// bool alone.
func TestServerTypeDeprecationSchedule(t *testing.T) {
	announced := time.Date(2025, 9, 24, 0, 0, 0, 0, time.UTC)
	unavailable := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)

	t.Run("not deprecated", func(t *testing.T) {
		st := hcloud.ServerType{ID: 1, Name: "cx22"}
		assert.False(t, st.IsDeprecated())
		assert.Equal(t, map[string]any{}, deprecationDict(st.Deprecation))
	})

	t.Run("deprecated with a schedule", func(t *testing.T) {
		st := hcloud.ServerType{
			ID:   2,
			Name: "cx11",
			Deprecation: &hcloud.DeprecationInfo{
				Announced:        announced,
				UnavailableAfter: unavailable,
			},
		}
		assert.True(t, st.IsDeprecated())
		assert.Equal(t, map[string]any{
			"announced":        "2025-09-24T00:00:00Z",
			"unavailableAfter": "2026-09-24T00:00:00Z",
		}, deprecationDict(st.Deprecation))
	})
}

// Category is the clean way to assert physical-CPU tenancy isolation. Reading
// it from the wrong field, or inferring it from the type slug, would misreport
// a dedicated-vCPU fleet as shared.
func TestServerTypeCategory(t *testing.T) {
	shared := hcloud.ServerType{Name: "cx22", CPUType: hcloud.CPUTypeShared, Category: "shared-vcpu"}
	dedicated := hcloud.ServerType{Name: "ccx13", CPUType: hcloud.CPUTypeDedicated, Category: "dedicated-vcpu"}

	assert.Equal(t, "shared-vcpu", shared.Category)
	assert.Equal(t, "dedicated-vcpu", dedicated.Category)

	// A type the API returned without a category reports an empty string
	// rather than a guess.
	assert.Equal(t, "", hcloud.ServerType{Name: "cx22"}.Category)
}

func TestServerTypeLocationIncludedTraffic(t *testing.T) {
	// Pricing entries carry only the location name, as hcloud decodes them.
	pricings := []hcloud.ServerTypeLocationPricing{
		{Location: &hcloud.Location{Name: "fsn1"}, IncludedTraffic: 21990232555520},
		{Location: &hcloud.Location{Name: "ash"}, IncludedTraffic: 1099511627776},
		{Location: nil, IncludedTraffic: 5},
	}

	// Synthetic: availability entry joined to its pricing by location name; no live project was checked.
	t.Run("matching location", func(t *testing.T) {
		got := serverTypeLocationIncludedTraffic(pricings, &hcloud.Location{ID: 1, Name: "fsn1"})
		if assert.NotNil(t, got) {
			assert.Equal(t, int64(21990232555520), *got)
		}
		got = serverTypeLocationIncludedTraffic(pricings, &hcloud.Location{ID: 4, Name: "ash"})
		if assert.NotNil(t, got) {
			assert.Equal(t, int64(1099511627776), *got)
		}
	})

	// Synthetic: a location with no pricing entry reads null, not 0; no live project was checked.
	t.Run("location without pricing", func(t *testing.T) {
		assert.Nil(t, serverTypeLocationIncludedTraffic(pricings, &hcloud.Location{ID: 3, Name: "hel1"}))
	})

	// Synthetic: availability entry without a location; no live project was checked.
	t.Run("no location", func(t *testing.T) {
		assert.Nil(t, serverTypeLocationIncludedTraffic(pricings, nil))
		assert.Nil(t, serverTypeLocationIncludedTraffic(pricings, &hcloud.Location{}))
	})

	// Synthetic: server type with no pricing at all; no live project was checked.
	t.Run("no pricings", func(t *testing.T) {
		assert.Nil(t, serverTypeLocationIncludedTraffic(nil, &hcloud.Location{Name: "fsn1"}))
	})
}
