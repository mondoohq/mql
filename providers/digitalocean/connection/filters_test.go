// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscoveryFiltersFromOpts(t *testing.T) {
	f := DiscoveryFiltersFromOpts(map[string]string{
		"regions":         "nyc1,sfo3",
		"exclude:regions": "ams3",
		"tags":            "production,web",
		"exclude:tags":    "temporary",
		"unrelated":       "ignored",
	}).General

	assert.Equal(t, []string{"nyc1", "sfo3"}, f.Regions)
	assert.Equal(t, []string{"ams3"}, f.ExcludeRegions)
	assert.Equal(t, []string{"production", "web"}, f.Tags)
	assert.Equal(t, []string{"temporary"}, f.ExcludeTags)
}

func TestGeneralDiscoveryFiltersHasFilters(t *testing.T) {
	assert.False(t, GeneralDiscoveryFilters{}.HasFilters())
	assert.True(t, GeneralDiscoveryFilters{Regions: []string{"nyc1"}}.HasFilters())
	assert.True(t, GeneralDiscoveryFilters{ExcludeRegions: []string{"nyc1"}}.HasFilters())
	assert.True(t, GeneralDiscoveryFilters{Tags: []string{"web"}}.HasFilters())
	assert.True(t, GeneralDiscoveryFilters{ExcludeTags: []string{"web"}}.HasFilters())
}

func TestIsFilteredOut(t *testing.T) {
	tests := []struct {
		name     string
		filters  GeneralDiscoveryFilters
		region   string
		tags     []string
		expected bool
	}{
		{
			name:     "no filters keeps everything",
			filters:  GeneralDiscoveryFilters{},
			region:   "nyc1",
			tags:     nil,
			expected: false,
		},
		{
			name:     "region in include list is kept",
			filters:  GeneralDiscoveryFilters{Regions: []string{"nyc1", "sfo3"}},
			region:   "sfo3",
			expected: false,
		},
		{
			name:     "region outside include list is dropped",
			filters:  GeneralDiscoveryFilters{Regions: []string{"nyc1"}},
			region:   "ams3",
			expected: true,
		},
		{
			name:     "excluded region is dropped",
			filters:  GeneralDiscoveryFilters{ExcludeRegions: []string{"ams3"}},
			region:   "ams3",
			expected: true,
		},
		{
			name:     "exclude wins over include for the same region",
			filters:  GeneralDiscoveryFilters{Regions: []string{"nyc1"}, ExcludeRegions: []string{"nyc1"}},
			region:   "nyc1",
			expected: true,
		},
		{
			name:     "region filters leave account-global resources alone",
			filters:  GeneralDiscoveryFilters{Regions: []string{"nyc1"}},
			region:   "",
			expected: false,
		},
		{
			name:     "any matching tag satisfies the include filter",
			filters:  GeneralDiscoveryFilters{Tags: []string{"production", "web"}},
			region:   "nyc1",
			tags:     []string{"database", "web"},
			expected: false,
		},
		{
			name:     "no matching tag drops the resource",
			filters:  GeneralDiscoveryFilters{Tags: []string{"production"}},
			region:   "nyc1",
			tags:     []string{"staging"},
			expected: true,
		},
		{
			name:     "an untagged resource cannot match an include-tag filter",
			filters:  GeneralDiscoveryFilters{Tags: []string{"production"}},
			region:   "nyc1",
			tags:     nil,
			expected: true,
		},
		{
			name:     "an untagged resource survives an exclude-only tag filter",
			filters:  GeneralDiscoveryFilters{ExcludeTags: []string{"temporary"}},
			region:   "nyc1",
			tags:     nil,
			expected: false,
		},
		{
			name:     "excluded tag drops the resource",
			filters:  GeneralDiscoveryFilters{ExcludeTags: []string{"temporary"}},
			region:   "nyc1",
			tags:     []string{"web", "temporary"},
			expected: true,
		},
		{
			name: "exclude tag wins over a matching include tag",
			filters: GeneralDiscoveryFilters{
				Tags:        []string{"web"},
				ExcludeTags: []string{"temporary"},
			},
			region:   "nyc1",
			tags:     []string{"web", "temporary"},
			expected: true,
		},
		{
			name:     "region and tag filters both have to pass",
			filters:  GeneralDiscoveryFilters{Regions: []string{"nyc1"}, Tags: []string{"web"}},
			region:   "ams3",
			tags:     []string{"web"},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, test.filters.IsFilteredOut(test.region, test.tags))
		})
	}
}
