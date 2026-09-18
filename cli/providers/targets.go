// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"errors"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// cliPreflight is what the pre-cobra parse of os.Args learns.
//
// It exists because AttachCLIs has to act on --discover before cobra runs: a
// meta-target directs its connections through that flag, so the providers a run
// needs are a function of its value alone, and that value is known before a
// single file is read (ADR 045).
type cliPreflight struct {
	ConnectorName string
	AutoUpdate    bool
	// Discover holds --discover as typed. DiscoverSet distinguishes an unset
	// flag from `--discover ""`: unset means the declared Auto subset, empty
	// means nothing at all, and pflag returns an empty slice for both.
	Discover    []string
	DiscoverSet bool
}

// targetUniverseFor enumerates the opt-ins reachable under a connector, or
// nothing when the connector is not a meta-target.
//
// The connector name is the target: no hardcoded list is needed, because the
// opt-ins name their target and the target is the connector (ADR 045).
func targetUniverseFor(connectorName string, existing providers.Providers) map[string][]providers.TargetDiscovery {
	if connectorName == "" {
		return nil
	}
	return providers.TargetUniverse(connectorName, existing, providers.DefaultProviders)
}

// ensureTargetDiscoveries installs the providers a meta-target run will need,
// before cobra runs and before the tree is read.
//
// The asymmetry between a named and an unset --discover is deliberate (ADR
// 045). An explicit `--discover k8s` is a statement that those assets matter,
// and quietly skipping them produces a clean report that is simply missing the
// thing the user asked about. An unset flag is a preference, and degrading to
// what is installed is the reasonable reading of it -- said out loud, so it is
// not a silent degradation.
func ensureTargetDiscoveries(pre cliPreflight, existing providers.Providers) error {
	universe := targetUniverseFor(pre.ConnectorName, existing)
	if len(universe) == 0 {
		// Not a meta-target connector. Every ordinary connector lands here.
		return nil
	}

	selected, unknown := providers.ResolveTargetDiscoveries(universe, pre.Discover, pre.DiscoverSet)
	if len(unknown) > 0 {
		// A typo that silently discovers nothing leaves a scan that succeeds
		// with a report quietly missing assets, so it fails and says what the
		// valid names are.
		return errors.New("unknown --discover value(s) " + strings.Join(unknown, ", ") +
			" for " + pre.ConnectorName + "; valid values are: " +
			strings.Join(append([]string{providers.DiscoveryAll, providers.DiscoveryAuto},
				providers.TargetDiscoveryNames(universe)...), ", "))
	}

	var missing []string
	for _, discovery := range selected {
		lookup := providers.ProviderLookup{Target: pre.ConnectorName, Discovery: discovery.OptIn.Discovery}
		if _, err := providers.EnsureProvider(lookup, pre.AutoUpdate, existing); err != nil {
			entry := discovery.OptIn.Discovery + " (" + discovery.Provider.Name + ")"
			if !slices.Contains(missing, entry) {
				missing = append(missing, entry)
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}

	if pre.DiscoverSet {
		return errors.New("cannot reach " + pre.ConnectorName + " discoveries: " + strings.Join(missing, ", "))
	}
	log.Warn().Str("connector", pre.ConnectorName).
		Msg("these discoveries were dropped because their provider is not installed and automatic installation is off: " +
			strings.Join(missing, ", "))
	return nil
}

// discoveriesForHelp is what --discover's help text lists for a connector.
//
// For a meta-target it is the enumerated opt-ins, so `mql shell iac --help`
// names what this machine can actually reach rather than the connector's
// static Discovery slice, which a meta-target leaves empty.
func discoveriesForHelp(connector *plugin.Connector, existing providers.Providers) []string {
	universe := targetUniverseFor(connector.Name, existing)
	if len(universe) == 0 {
		return connector.Discovery
	}
	return append(slices.Clone(connector.Discovery), providers.TargetDiscoveryNames(universe)...)
}
