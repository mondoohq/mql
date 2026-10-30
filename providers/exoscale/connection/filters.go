// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/util/filteropts"
)

// Filter option keys, as written after --filters.
const (
	FilterLabels        = "labels"
	FilterExcludeLabels = "exclude:labels"
)

// FilterOptKeys are the --filters keys the provider understands. Anything else
// is dropped rather than stored, so a typo reads as a filter that did nothing
// instead of one that appears accepted.
var FilterOptKeys = []string{FilterLabels, FilterExcludeLabels}

// DiscoveryFilters narrows which resources the listers return, and therefore
// which ones discovery turns into assets, so a filtered scan and a plain query
// see the same set. Zones are narrowed by --zones instead.
type DiscoveryFilters struct {
	Labels        []LabelSelector
	ExcludeLabels []LabelSelector
}

// LabelSelector matches a label by key, and by value when one is given:
// `env=prod` matches only that pair, a bare `env` matches any value.
type LabelSelector struct {
	Key   string
	Value string
	// AnyValue is set for a bare key.
	AnyValue bool
}

// DiscoveryFiltersFromOpts reads the filters ParseCLI stored in the connection
// options. Each option holds a comma-separated list of selectors.
func DiscoveryFiltersFromOpts(opts map[string]string) DiscoveryFilters {
	return DiscoveryFilters{
		Labels:        parseLabelSelectors(filteropts.ParseCsvSliceOpt(opts, FilterLabels)),
		ExcludeLabels: parseLabelSelectors(filteropts.ParseCsvSliceOpt(opts, FilterExcludeLabels)),
	}
}

func parseLabelSelectors(raw []string) []LabelSelector {
	out := make([]LabelSelector, 0, len(raw))
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		k, v, ok := strings.Cut(r, "=")
		out = append(out, LabelSelector{Key: strings.TrimSpace(k), Value: strings.TrimSpace(v), AnyValue: !ok})
	}
	return out
}

// HasFilters reports whether any filter is set.
func (f DiscoveryFilters) HasFilters() bool {
	return len(f.Labels) > 0 || len(f.ExcludeLabels) > 0
}

// IsFilteredOut reports whether a resource carrying these labels is dropped.
// An include filter keeps a resource matching any of its selectors, so a
// resource without labels, such as a security group or a DBaaS service,
// cannot satisfy one. An exclude match drops the resource regardless.
func (f DiscoveryFilters) IsFilteredOut(labels map[string]string) bool {
	if len(f.Labels) > 0 && !matchesAny(labels, f.Labels) {
		return true
	}
	return matchesAny(labels, f.ExcludeLabels)
}

func matchesAny(labels map[string]string, selectors []LabelSelector) bool {
	for _, s := range selectors {
		v, ok := labels[s.Key]
		if ok && (s.AnyValue || v == s.Value) {
			return true
		}
	}
	return false
}
