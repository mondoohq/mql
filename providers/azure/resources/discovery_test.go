// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
)

func TestGetDiscoveryTargets(t *testing.T) {
	config := &inventory.Config{
		Discover: &inventory.Discovery{
			Targets: []string{},
		},
	}
	// test all with other stuff
	config.Discover.Targets = []string{"all", "projects", "instances"}
	require.Equal(t, allDiscovery(), getDiscoveryTargets(config))

	// test just all
	config.Discover.Targets = []string{"all"}
	require.Equal(t, allDiscovery(), getDiscoveryTargets(config))

	// test auto with other stuff
	config.Discover.Targets = []string{"auto", "postgres-servers", "keyvaults-vaults"}
	res := append(Auto, []string{DiscoveryPostgresServers, DiscoveryKeyVaults}...)
	sort.Strings(res)
	targets := getDiscoveryTargets(config)
	sort.Strings(targets)
	require.Equal(t, res, targets)

	// test just auto
	config.Discover.Targets = []string{"auto"}
	require.Equal(t, Auto, getDiscoveryTargets(config))

	// test random
	config.Discover.Targets = []string{"postgres-servers", "keyvaults-vaults", "instances"}
	require.Equal(t, []string{DiscoveryPostgresServers, DiscoveryKeyVaults, DiscoveryInstances}, getDiscoveryTargets(config))

	// test standard cli run without options
	config.Discover.Targets = []string{}
	require.Equal(t, Auto, getDiscoveryTargets(config))
}
