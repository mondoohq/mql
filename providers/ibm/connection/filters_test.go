// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscoveryFiltersFromOpts(t *testing.T) {
	f := DiscoveryFiltersFromOpts(map[string]string{
		FilterTags:        "env:prod, team ,",
		FilterExcludeTags: "tier:dev",
	})
	assert.Equal(t, []string{"env:prod", "team"}, f.Tags)
	assert.Equal(t, []string{"tier:dev"}, f.ExcludeTags)
	assert.True(t, f.HasFilters())

	assert.False(t, DiscoveryFiltersFromOpts(map[string]string{}).HasFilters())
}

func TestIsFilteredOut(t *testing.T) {
	include := DiscoveryFilters{Tags: []string{"env:prod", "team"}}
	assert.False(t, include.IsFilteredOut([]string{"env:prod"}), "exact tag")
	assert.False(t, include.IsFilteredOut([]string{"ENV:Prod"}), "tags compare case-insensitively")
	assert.False(t, include.IsFilteredOut([]string{"team:core"}), "a bare key matches any value")
	assert.False(t, include.IsFilteredOut([]string{"team"}), "a bare key matches the plain tag")
	assert.True(t, include.IsFilteredOut([]string{"env:dev"}), "a key:value selector needs the value")
	assert.True(t, include.IsFilteredOut([]string{"teams:x"}), "a bare key is not a prefix match")
	assert.True(t, include.IsFilteredOut(nil), "an untagged resource cannot satisfy an include filter")

	exclude := DiscoveryFilters{ExcludeTags: []string{"tier:dev"}}
	assert.True(t, exclude.IsFilteredOut([]string{"env:prod", "tier:dev"}))
	assert.False(t, exclude.IsFilteredOut(nil), "an exclude filter keeps an untagged resource")

	both := DiscoveryFilters{Tags: []string{"env:prod"}, ExcludeTags: []string{"tier:dev"}}
	assert.True(t, both.IsFilteredOut([]string{"env:prod", "tier:dev"}), "an exclude match wins")

	assert.False(t, DiscoveryFilters{}.IsFilteredOut(nil))
}
