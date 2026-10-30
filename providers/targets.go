// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"sort"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Discovery names every meta-target understands, on top of the enumerated
// opt-ins.
const (
	// DiscoveryAuto is what an unset --discover expands to: the opt-ins that
	// declared themselves Auto.
	DiscoveryAuto = "auto"
	// DiscoveryAll is every enumerated opt-in, whether or not it is Auto.
	DiscoveryAll = "all"
)

// TargetDiscovery is one opt-in resolved to the provider that declares it.
type TargetDiscovery struct {
	Provider *Provider
	OptIn    plugin.TargetOptIn
}

// TargetUniverse enumerates every opt-in for target, keyed by discovery name.
//
// installed is searched first and is authoritative: a provider's <name>.json on
// disk is newer than whatever DefaultProviders recorded at release time, so an
// installed provider replaces the defaults entry for the same provider ID
// rather than being merged with it. defaults covers everything not installed.
// Neither is a fallback for the other; they are one lookup with a defined
// order, the same one EnsureProvider resolves against (ADR 045).
//
// One discovery name can carry several opt-ins, from one provider or from
// several, so the values are slices.
func TargetUniverse(target string, installed, defaults Providers) map[string][]TargetDiscovery {
	if target == "" {
		return nil
	}

	res := map[string][]TargetDiscovery{}
	seenProvider := map[string]bool{}

	add := func(provider *Provider) {
		if provider == nil || provider.Provider == nil || seenProvider[provider.ID] {
			return
		}
		seenProvider[provider.ID] = true
		for _, optIn := range provider.TargetOptIns(target) {
			if optIn.Discovery == "" {
				continue
			}
			res[optIn.Discovery] = append(res[optIn.Discovery], TargetDiscovery{Provider: provider, OptIn: optIn})
		}
	}

	for _, provider := range installed {
		add(provider)
	}
	for _, provider := range defaults {
		add(provider)
	}

	return res
}

// TargetDiscoveryNames returns the discovery names enumerated for a target,
// sorted. It is what supplies --discover's help text, so `mql shell iac --help`
// lists what this machine can actually reach rather than a static slice.
func TargetDiscoveryNames(universe map[string][]TargetDiscovery) []string {
	names := make([]string, 0, len(universe))
	for name := range universe {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ResolveTargetDiscoveries applies ADR 045's --discover table: requested names
// are matched against discovery names, an unset flag selects the Auto subset,
// and "all" selects every enumerated opt-in.
//
// requestedSet distinguishes an unset flag from `--discover ""`. They mean
// different things -- the default set, and nothing at all -- and pflag returns
// an empty slice for both.
//
// An unknown name is returned in unknown rather than ignored: a typo that
// silently discovers nothing leaves a scan that succeeds with a report quietly
// missing assets. The caller decides what to do with that; selected is still
// filled in from the names that did resolve.
func ResolveTargetDiscoveries(universe map[string][]TargetDiscovery, requested []string, requestedSet bool) (selected []TargetDiscovery, unknown []string) {
	if len(universe) == 0 {
		return nil, nil
	}

	if !requestedSet {
		requested = []string{DiscoveryAuto}
	}

	// Cleaned rather than used as given, because a list flag passed "" arrives
	// as one empty entry rather than as no entries at all.
	names := make([]string, 0, len(requested))
	for _, name := range requested {
		if name != "" {
			names = append(names, name)
		}
	}

	appendAll := func(keep func(plugin.TargetOptIn) bool) {
		for _, name := range TargetDiscoveryNames(universe) {
			for _, discovery := range universe[name] {
				if keep(discovery.OptIn) {
					selected = append(selected, discovery)
				}
			}
		}
	}

	seen := map[string]bool{}
	for _, name := range names {
		switch name {
		case DiscoveryAll:
			appendAll(func(plugin.TargetOptIn) bool { return true })
			// Every opt-in is in; anything else named alongside is redundant
			// rather than wrong, so stop instead of adding duplicates.
			return selected, unknown
		case DiscoveryAuto:
			appendAll(func(optIn plugin.TargetOptIn) bool { return optIn.Auto })
		default:
			discoveries, ok := universe[name]
			if !ok {
				unknown = append(unknown, name)
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			selected = append(selected, discoveries...)
		}
	}

	return selected, unknown
}
