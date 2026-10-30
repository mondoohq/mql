// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscoveryFiltersFromOpts(t *testing.T) {
	f := DiscoveryFiltersFromOpts(map[string]string{
		"regions":               "cn-hangzhou,ap-southeast-1",
		"exclude:regions":       "cn-beijing",
		"tag:Environment":       "production",
		"tag:Team":              "platform,security",
		"exclude:tag:Lifecycle": "temporary",
		// unrelated connection options must not leak into the filters
		"region":        "cn-hangzhou",
		"access-key-id": "example",
	}).General

	assert.Equal(t, []string{"cn-hangzhou", "ap-southeast-1"}, f.Regions)
	assert.Equal(t, []string{"cn-beijing"}, f.ExcludeRegions)
	assert.Equal(t, map[string]string{"Environment": "production", "Team": "platform,security"}, f.Tags)
	assert.Equal(t, map[string]string{"Lifecycle": "temporary"}, f.ExcludeTags)
}

func TestGeneralDiscoveryFiltersHasTags(t *testing.T) {
	assert.False(t, GeneralDiscoveryFilters{}.HasTags())
	assert.False(t, GeneralDiscoveryFilters{Regions: []string{"cn-hangzhou"}}.HasTags())
	assert.True(t, GeneralDiscoveryFilters{Tags: map[string]string{"a": "b"}}.HasTags())
	assert.True(t, GeneralDiscoveryFilters{ExcludeTags: map[string]string{"a": "b"}}.HasTags())
}

func TestIsFilteredOutByTags(t *testing.T) {
	tests := []struct {
		name     string
		filters  GeneralDiscoveryFilters
		tags     map[string]string
		filtered bool
	}{
		{
			name:     "no filters keeps everything",
			filters:  GeneralDiscoveryFilters{},
			tags:     map[string]string{"Environment": "dev"},
			filtered: false,
		},
		{
			name:     "matching include tag is kept",
			filters:  GeneralDiscoveryFilters{Tags: map[string]string{"Environment": "production"}},
			tags:     map[string]string{"Environment": "production"},
			filtered: false,
		},
		{
			name:     "non-matching include tag is dropped",
			filters:  GeneralDiscoveryFilters{Tags: map[string]string{"Environment": "production"}},
			tags:     map[string]string{"Environment": "dev"},
			filtered: true,
		},
		{
			name:     "untagged resource is dropped when an include tag is set",
			filters:  GeneralDiscoveryFilters{Tags: map[string]string{"Environment": "production"}},
			tags:     map[string]string{},
			filtered: true,
		},
		{
			name:     "any value in a csv include list matches",
			filters:  GeneralDiscoveryFilters{Tags: map[string]string{"Environment": "production,staging"}},
			tags:     map[string]string{"Environment": "staging"},
			filtered: false,
		},
		{
			name:     "matching exclude tag is dropped",
			filters:  GeneralDiscoveryFilters{ExcludeTags: map[string]string{"Lifecycle": "temporary"}},
			tags:     map[string]string{"Lifecycle": "temporary"},
			filtered: true,
		},
		{
			// exclude must win, otherwise an explicit opt-out is silently
			// overridden by a broader include filter
			name: "exclude beats include",
			filters: GeneralDiscoveryFilters{
				Tags:        map[string]string{"Environment": "production"},
				ExcludeTags: map[string]string{"Lifecycle": "temporary"},
			},
			tags:     map[string]string{"Environment": "production", "Lifecycle": "temporary"},
			filtered: true,
		},
		{
			name:     "exclude on an unrelated key keeps the resource",
			filters:  GeneralDiscoveryFilters{ExcludeTags: map[string]string{"Lifecycle": "temporary"}},
			tags:     map[string]string{"Environment": "production"},
			filtered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.filtered, tt.filters.IsFilteredOutByTags(tt.tags))
		})
	}
}

func TestApplyRegionFilters(t *testing.T) {
	all := []string{"cn-hangzhou", "cn-beijing", "ap-southeast-1"}

	t.Run("no filters returns everything", func(t *testing.T) {
		assert.Equal(t, all, GeneralDiscoveryFilters{}.applyRegionFilters(all))
	})

	t.Run("include narrows to the listed regions", func(t *testing.T) {
		f := GeneralDiscoveryFilters{Regions: []string{"cn-hangzhou", "ap-southeast-1"}}
		assert.Equal(t, []string{"cn-hangzhou", "ap-southeast-1"}, f.applyRegionFilters(all))
	})

	t.Run("exclude drops the listed regions", func(t *testing.T) {
		f := GeneralDiscoveryFilters{ExcludeRegions: []string{"cn-beijing"}}
		assert.Equal(t, []string{"cn-hangzhou", "ap-southeast-1"}, f.applyRegionFilters(all))
	})

	t.Run("exclude beats include", func(t *testing.T) {
		f := GeneralDiscoveryFilters{
			Regions:        []string{"cn-hangzhou", "cn-beijing"},
			ExcludeRegions: []string{"cn-beijing"},
		}
		assert.Equal(t, []string{"cn-hangzhou"}, f.applyRegionFilters(all))
	})

	// A filter that selects nothing must yield nothing rather than falling back
	// to every region, which would scan far more than the user asked for.
	t.Run("an include list matching nothing yields no regions", func(t *testing.T) {
		f := GeneralDiscoveryFilters{Regions: []string{"us-east-1"}}
		assert.Empty(t, f.applyRegionFilters(all))
	})
}
