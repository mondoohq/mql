// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"slices"

	"go.mondoo.com/mql/providers-sdk/v1/util/filteropts"
)

// DiscoveryFilters narrows which objects discovery turns into assets, and which
// objects the corresponding MQL listings return, so a scan and a plain query see
// the same set.
//
// DigitalOcean's Discover() enumerates each service directly rather than reading
// back through the MQL listers, so both call sites share the predicates below
// instead of relying on a single choke point.
type DiscoveryFilters struct {
	General GeneralDiscoveryFilters
}

// GeneralDiscoveryFilters holds the filters that apply to every service.
//
// DigitalOcean tags are flat labels rather than key/value pairs, so the tag
// filters take a list of tag names and match a resource carrying any of them.
type GeneralDiscoveryFilters struct {
	Regions        []string
	ExcludeRegions []string
	Tags           []string
	ExcludeTags    []string
}

// DiscoveryFiltersFromOpts reads the filter set out of the connection options
// that ParseCLI populated from --filters.
func DiscoveryFiltersFromOpts(opts map[string]string) DiscoveryFilters {
	return DiscoveryFilters{
		General: GeneralDiscoveryFilters{
			Regions:        filteropts.ParseCsvSliceOpt(opts, "regions"),
			ExcludeRegions: filteropts.ParseCsvSliceOpt(opts, "exclude:regions"),
			Tags:           filteropts.ParseCsvSliceOpt(opts, "tags"),
			ExcludeTags:    filteropts.ParseCsvSliceOpt(opts, "exclude:tags"),
		},
	}
}

// HasFilters reports whether any filter was set. Callers gate optional lookups
// on this so an unfiltered scan does not pay for data nobody asked for.
func (f GeneralDiscoveryFilters) HasFilters() bool {
	return len(f.Regions) > 0 || len(f.ExcludeRegions) > 0 ||
		len(f.Tags) > 0 || len(f.ExcludeTags) > 0
}

// IsFilteredOut reports whether a resource in the given region and carrying the
// given tags should be skipped.
//
// An empty region means the resource has no region dimension at all (cloud
// firewalls are account-global), and region filters leave those alone — a
// global resource applies in every selected region. Tags are matched for every
// resource, so a resource that carries no tags cannot satisfy an include-tag
// filter and is dropped by one.
func (f GeneralDiscoveryFilters) IsFilteredOut(region string, tags []string) bool {
	return f.isFilteredOutByRegion(region) || f.isFilteredOutByTags(tags)
}

// isFilteredOutByRegion reports whether the region fails the region filters.
func (f GeneralDiscoveryFilters) isFilteredOutByRegion(region string) bool {
	if region == "" {
		return false
	}
	if len(f.Regions) > 0 && !slices.Contains(f.Regions, region) {
		return true
	}
	return slices.Contains(f.ExcludeRegions, region)
}

// isFilteredOutByTags reports whether the tag set fails the tag filters. An
// exclude match drops the resource regardless of the include filters.
func (f GeneralDiscoveryFilters) isFilteredOutByTags(tags []string) bool {
	if len(f.Tags) > 0 && !containsAny(tags, f.Tags) {
		return true
	}
	return containsAny(tags, f.ExcludeTags)
}

// containsAny reports whether tags holds at least one of the wanted labels.
func containsAny(tags, wanted []string) bool {
	for _, w := range wanted {
		if slices.Contains(tags, w) {
			return true
		}
	}
	return false
}
