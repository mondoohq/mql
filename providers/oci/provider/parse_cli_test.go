// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/provider"
	"go.mondoo.com/mql/providers/oci/resources"
	"go.mondoo.com/mql/types"
)

func discoverFlag(targets ...string) *llx.Primitive {
	prims := make([]*llx.Primitive, len(targets))
	for i, t := range targets {
		prims[i] = llx.StringPrimitive(t)
	}
	return llx.ArrayPrimitive(prims, types.String)
}

func TestParseCLI_DiscoverFlag(t *testing.T) {
	tests := []struct {
		name     string
		flags    map[string]*llx.Primitive
		expected []string
	}{
		{
			name:     "no flag defaults to auto",
			flags:    map[string]*llx.Primitive{},
			expected: []string{resources.DiscoveryAuto},
		},
		{
			name: "single target",
			flags: map[string]*llx.Primitive{
				"discover": discoverFlag(resources.DiscoveryUsers),
			},
			expected: []string{resources.DiscoveryUsers},
		},
		{
			name: "multiple targets preserve order",
			flags: map[string]*llx.Primitive{
				"discover": discoverFlag(
					resources.DiscoveryUsers,
					resources.DiscoverySecurityLists,
					resources.DiscoveryBuckets,
				),
			},
			expected: []string{
				resources.DiscoveryUsers,
				resources.DiscoverySecurityLists,
				resources.DiscoveryBuckets,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := provider.Init()
			res, err := svc.ParseCLI(&plugin.ParseCLIReq{
				Connector: "oci",
				Flags:     tc.flags,
			})
			require.NoError(t, err)
			require.NotNil(t, res.Asset)
			require.Len(t, res.Asset.Connections, 1)

			conf := res.Asset.Connections[0]
			require.NotNil(t, conf.Discover, "Discover must be set so the provider runs discovery")
			assert.Equal(t, tc.expected, conf.Discover.Targets)
		})
	}
}
