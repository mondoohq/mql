// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/util/filteropts"
)

// Filter option keys, as written after --filters.
const (
	FilterTags        = "tags"
	FilterExcludeTags = "exclude:tags"
)

// FilterOptKeys are the --filters keys the provider understands. Anything else
// is dropped rather than stored, so a typo reads as a filter that did nothing
// instead of one that appears accepted.
var FilterOptKeys = []string{FilterTags, FilterExcludeTags}

// DiscoveryFilters narrows which resources the listers return, and therefore
// which ones discovery turns into assets, so a filtered scan and a plain query
// see the same set. Regions are narrowed by --regions instead.
type DiscoveryFilters struct {
	Tags        []string
	ExcludeTags []string
}

// DiscoveryFiltersFromOpts reads the filters ParseCLI stored in the connection
// options. Each option holds a comma-separated list of tag selectors.
func DiscoveryFiltersFromOpts(opts map[string]string) DiscoveryFilters {
	return DiscoveryFilters{
		Tags:        cleanSelectors(filteropts.ParseCsvSliceOpt(opts, FilterTags)),
		ExcludeTags: cleanSelectors(filteropts.ParseCsvSliceOpt(opts, FilterExcludeTags)),
	}
}

func cleanSelectors(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// HasFilters reports whether any filter is set.
func (f DiscoveryFilters) HasFilters() bool {
	return len(f.Tags) > 0 || len(f.ExcludeTags) > 0
}

// IsFilteredOut reports whether a resource carrying these tags is dropped. An
// include filter keeps a resource matching any of its selectors, so an
// untagged resource cannot satisfy one. An exclude match drops the resource
// regardless.
func (f DiscoveryFilters) IsFilteredOut(tags []string) bool {
	if len(f.Tags) > 0 && !matchesAny(tags, f.Tags) {
		return true
	}
	return matchesAny(tags, f.ExcludeTags)
}

// matchesAny reports whether a tag matches a selector. IBM Cloud tags are
// plain strings, by convention `key:value`, and compare case-insensitively. A
// selector matches the identical tag, and a selector without a colon also
// matches any `key:value` tag with that key: `env` matches `env:prod`.
func matchesAny(tags []string, selectors []string) bool {
	for _, s := range selectors {
		for _, t := range tags {
			if strings.EqualFold(t, s) {
				return true
			}
			if !strings.Contains(s, ":") {
				if k, _, ok := strings.Cut(t, ":"); ok && strings.EqualFold(strings.TrimSpace(k), s) {
					return true
				}
			}
		}
	}
	return false
}
