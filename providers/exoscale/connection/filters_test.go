// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscoveryFiltersFromOpts(t *testing.T) {
	f := DiscoveryFiltersFromOpts(map[string]string{
		FilterLabels:        "env=prod, team",
		FilterExcludeLabels: "tier=dev",
	})
	assert.Equal(t, []LabelSelector{{Key: "env", Value: "prod"}, {Key: "team", AnyValue: true}}, f.Labels)
	assert.Equal(t, []LabelSelector{{Key: "tier", Value: "dev"}}, f.ExcludeLabels)
	assert.True(t, f.HasFilters())
	assert.False(t, DiscoveryFiltersFromOpts(map[string]string{}).HasFilters())
}

func TestIsFilteredOut(t *testing.T) {
	f := DiscoveryFiltersFromOpts(map[string]string{
		FilterLabels:        "env=prod,team",
		FilterExcludeLabels: "legacy",
	})
	// Matches the env pair.
	assert.False(t, f.IsFilteredOut(map[string]string{"env": "prod"}))
	// A bare key matches any value.
	assert.False(t, f.IsFilteredOut(map[string]string{"team": "web"}))
	// Same key, other value.
	assert.True(t, f.IsFilteredOut(map[string]string{"env": "staging"}))
	// No labels cannot satisfy an include filter.
	assert.True(t, f.IsFilteredOut(nil))
	// Exclude wins over a matching include.
	assert.True(t, f.IsFilteredOut(map[string]string{"env": "prod", "legacy": "yes"}))

	// Without filters nothing is dropped, labelled or not.
	none := DiscoveryFilters{}
	assert.False(t, none.IsFilteredOut(nil))
	assert.False(t, none.IsFilteredOut(map[string]string{"env": "prod"}))

	// Exclude alone keeps unlabelled resources.
	ex := DiscoveryFiltersFromOpts(map[string]string{FilterExcludeLabels: "env=dev"})
	assert.False(t, ex.IsFilteredOut(nil))
	assert.True(t, ex.IsFilteredOut(map[string]string{"env": "dev"}))
}
