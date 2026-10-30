// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"slices"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/util/filteropts"
)

// DiscoveryFilters narrows which objects discovery turns into assets, and which
// objects the corresponding MQL listings return. Filters are applied in the
// listers rather than in discovery, so a scan and a plain query see the same
// set.
type DiscoveryFilters struct {
	General GeneralDiscoveryFilters
}

// GeneralDiscoveryFilters holds the filters that apply to every service.
type GeneralDiscoveryFilters struct {
	Regions        []string
	ExcludeRegions []string
	// Tags values may be a comma-separated list, so `tag:env=prod,staging`
	// matches either value.
	Tags map[string]string
	// ExcludeTags values may be a comma-separated list, like Tags.
	ExcludeTags map[string]string
}

// DiscoveryFiltersFromOpts reads the filter set out of the connection options
// that ParseCLI populated from --filters.
func DiscoveryFiltersFromOpts(opts map[string]string) DiscoveryFilters {
	return DiscoveryFilters{
		General: GeneralDiscoveryFilters{
			Regions:        filteropts.ParseCsvSliceOpt(opts, "regions"),
			ExcludeRegions: filteropts.ParseCsvSliceOpt(opts, "exclude:regions"),
			Tags:           parseMapOpt(opts, "tag:"),
			ExcludeTags:    parseMapOpt(opts, "exclude:tag:"),
		},
	}
}

// parseMapOpt collects the options sharing a prefix into a map keyed by the
// remainder, so `tag:env=prod` becomes {"env": "prod"}.
func parseMapOpt(opts map[string]string, prefix string) map[string]string {
	res := map[string]string{}
	for k, v := range opts {
		if key, ok := strings.CutPrefix(k, prefix); ok && key != "" {
			res[key] = v
		}
	}
	return res
}

// HasTags reports whether any tag filter was set. Callers gate their tag lookup
// on this so an unfiltered scan does not pay for tags nobody asked for.
func (f GeneralDiscoveryFilters) HasTags() bool {
	return len(f.Tags) > 0 || len(f.ExcludeTags) > 0
}

// IsFilteredOutByTags reports whether a resource carrying these tags should be
// skipped.
func (f GeneralDiscoveryFilters) IsFilteredOutByTags(resourceTags map[string]string) bool {
	return !f.matchesIncludeTags(resourceTags) || f.matchesExcludeTags(resourceTags)
}

// matchesIncludeTags reports whether the resource matches at least one include
// filter. With no include filters set, everything matches.
func (f GeneralDiscoveryFilters) matchesIncludeTags(resourceTags map[string]string) bool {
	if len(f.Tags) == 0 {
		return true
	}
	for k, csv := range f.Tags {
		for v := range strings.SplitSeq(csv, ",") {
			if tagValue, ok := resourceTags[k]; ok && tagValue == v {
				return true
			}
		}
	}
	return false
}

// matchesExcludeTags reports whether the resource matches any exclude filter,
// in which case it is dropped regardless of the include filters.
func (f GeneralDiscoveryFilters) matchesExcludeTags(resourceTags map[string]string) bool {
	for k, csv := range f.ExcludeTags {
		for v := range strings.SplitSeq(csv, ",") {
			if tagValue, ok := resourceTags[k]; ok && tagValue == v {
				return true
			}
		}
	}
	return false
}

// applyRegionFilters narrows a region list to the included regions and drops the
// excluded ones. An include list that matches nothing yields no regions, which
// is the honest answer for a filter that selects nothing.
func (f GeneralDiscoveryFilters) applyRegionFilters(regions []string) []string {
	if len(f.Regions) == 0 && len(f.ExcludeRegions) == 0 {
		return regions
	}

	res := make([]string, 0, len(regions))
	for _, r := range regions {
		if len(f.Regions) > 0 && !slices.Contains(f.Regions, r) {
			continue
		}
		if slices.Contains(f.ExcludeRegions, r) {
			continue
		}
		res = append(res, r)
	}
	return res
}
