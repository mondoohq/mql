// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"slices"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/util/filteropts"
)

// DiscoveryFilters narrows what the Azure provider discovers. It mirrors the
// AWS provider's DiscoveryFilters so the two share the same shape: the raw
// --filters key/value options carried on inventory.Discovery.Filter are parsed
// into this typed struct once, at connection time, and read from conn.Filters
// during discovery.
type DiscoveryFilters struct {
	Subscriptions SubscriptionsFilter
	// General holds the filters that apply to every discovered resource,
	// regardless of service.
	General GeneralDiscoveryFilters
	// PropagateSubscriptionTags merges each subscription's tags into every asset
	// discovered under that subscription (an asset's own labels win on collision).
	// Off by default. Mirrors the GCP provider's PropagateProjectLabels and the
	// AWS provider's PropagateAccountTags.
	PropagateSubscriptionTags bool
	// SubscriptionTags is an optional injected override. When non-empty it is used
	// instead of fetching each subscription's tags from the API, and applies to
	// every discovered subscription. Mirrors the AWS provider's AccountTags.
	SubscriptionTags map[string]string
}

// SubscriptionsFilter selects which subscriptions to discover. An empty Include
// means "all subscriptions"; a non-empty Include restricts discovery to exactly
// those subscriptions. Exclude removes matches when Include is empty.
type SubscriptionsFilter struct {
	Exclude []string
	Include []string
}

// IsFilteredOut reports whether the subscription with the given ID should be
// skipped during discovery. A non-empty Include list short-circuits: only
// subscriptions in it are kept, and Exclude is ignored. When Include is empty,
// a subscription is skipped only if it appears in Exclude.
//
// note: if this function returns `true`, it means that the subscription should
// be skipped.
func (f SubscriptionsFilter) IsFilteredOut(subscriptionID string) bool {
	if len(f.Include) > 0 {
		return !slices.Contains(f.Include, subscriptionID)
	}
	return slices.Contains(f.Exclude, subscriptionID)
}

// GeneralDiscoveryFilters narrows discovery by ARM resource tag. It mirrors the
// AWS provider's filter of the same name, including its matching semantics, so
// that `--filters tag:env=prod` selects the same way on both clouds.
//
// Azure applies these client-side. The generic ARM list call already returns
// each resource's tags, so filtering here costs nothing extra -- unlike AWS,
// there is no per-resource tag lookup to avoid.
type GeneralDiscoveryFilters struct {
	// Tags restricts discovery to resources carrying at least one of these
	// key/value pairs. Values may be a CSV list, e.g. "env": "prod,staging".
	Tags map[string]string
	// ExcludeTags drops resources carrying any of these key/value pairs. It is
	// applied after Tags, so an excluded resource stays excluded even when it
	// also matches an include.
	ExcludeTags map[string]string
}

// HasTags reports whether any tag filter was requested. Callers use it to skip
// a tag lookup they would otherwise have to pay for.
func (f GeneralDiscoveryFilters) HasTags() bool {
	return len(f.Tags) > 0 || len(f.ExcludeTags) > 0
}

// IsFilteredOutByTags reports whether a resource carrying resourceTags should be
// skipped during discovery.
//
// note: if this function returns `true`, it means that the resource should be
// skipped.
func (f GeneralDiscoveryFilters) IsFilteredOutByTags(resourceTags map[string]string) bool {
	return !f.MatchesIncludeTags(resourceTags) || f.MatchesExcludeTags(resourceTags)
}

// MatchesIncludeTags reports whether resourceTags satisfies the include filter.
// An empty filter matches everything.
//
// Matching is ANY, not ALL: a resource is kept when it matches at least one of
// the requested key/value pairs. This is deliberately the same rule the AWS
// provider uses -- `--filters tag:env=prod --filters tag:team=infra` reads as
// "prod or infra" on both providers rather than meaning one thing here and
// another there.
func (f GeneralDiscoveryFilters) MatchesIncludeTags(resourceTags map[string]string) bool {
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

// MatchesExcludeTags reports whether resourceTags matches the exclude filter.
//
// note: if this function returns `true`, it means that the resource should be
// skipped.
func (f GeneralDiscoveryFilters) MatchesExcludeTags(resourceTags map[string]string) bool {
	for k, csv := range f.ExcludeTags {
		for v := range strings.SplitSeq(csv, ",") {
			if tagValue, ok := resourceTags[k]; ok && tagValue == v {
				return true
			}
		}
	}
	return false
}

// SubscriptionTagFilterPrefix is the --filters key prefix that names the tags
// to attribute to a subscription's assets, as in
// `--filters subscription-tag:env=prod`. Staged discovery also writes it: a
// stage-2 connection is scoped to exactly one subscription, so "the tags of
// this subscription" and "the tag override for this connection" are the same
// thing, and stage 1 can hand over the tags it already read rather than making
// stage 2 fetch them again.
const SubscriptionTagFilterPrefix = "subscription-tag:"

// DiscoveryFiltersFromOpts parses the raw --filters key/value options into the
// typed DiscoveryFilters. It is nil-safe: a nil opts map yields empty filters.
func DiscoveryFiltersFromOpts(opts map[string]string) DiscoveryFilters {
	return DiscoveryFilters{
		Subscriptions: SubscriptionsFilter{
			Include: filteropts.ParseCsvSliceOpt(opts, "subscriptions"),
			Exclude: filteropts.ParseCsvSliceOpt(opts, "subscriptions-exclude"),
		},
		General: GeneralDiscoveryFilters{
			Tags:        parseMapOpt(opts, "tag:"),
			ExcludeTags: parseMapOpt(opts, "exclude:tag:"),
		},
		PropagateSubscriptionTags: filteropts.ParseBoolOpt(opts, "propagate-subscription-tags", false),
		SubscriptionTags:          parseMapOpt(opts, SubscriptionTagFilterPrefix),
	}
}

// parseMapOpt collects all opts whose key starts with keyPrefix into a map,
// trimming the prefix from each key. Empty keys or values are skipped. Returns a
// non-nil empty map when nothing matches.
func parseMapOpt(opts map[string]string, keyPrefix string) map[string]string {
	res := map[string]string{}
	for k, v := range opts {
		if k == "" || v == "" {
			continue
		}
		if !strings.HasPrefix(k, keyPrefix) {
			continue
		}
		res[strings.TrimPrefix(k, keyPrefix)] = v
	}
	return res
}
