// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	subscriptions "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestAllResolvedResources(t *testing.T) {
	expected := []string{
		DiscoverySubscriptions,
		DiscoveryInstancesApi,
		DiscoverySqlServers,
		DiscoveryPostgresFlexibleServers,
		DiscoveryMySqlFlexibleServers,
		DiscoveryAksClusters,
		DiscoveryAppServiceApps,
		DiscoveryCacheRedis,
		DiscoveryBatchAccounts,
		DiscoveryStorageAccounts,
		DiscoveryKeyVaults,
		DiscoveryManagedHsms,
		DiscoveryIotHubs,
		DiscoverySecurityGroups,
		DiscoveryCosmosDb,
		DiscoveryVirtualNetworks,
		DiscoveryContainerRegistries,
		DiscoveryRecoveryServicesVaults,
		DiscoverySynapseWorkspaces,
		DiscoveryDataFactories,
		DiscoveryFunctionApps,
		DiscoveryApplicationGateways,
		DiscoveryFirewalls,
		DiscoveryContainerApps,
		DiscoveryCognitiveServices,
		DiscoveryStorageContainers,
	}
	require.ElementsMatch(t, expected, All)
}

func TestAutoResolvedResources(t *testing.T) {
	expected := []string{
		DiscoverySubscriptions,
		DiscoverySqlServers,
		DiscoveryPostgresFlexibleServers,
		DiscoveryMySqlFlexibleServers,
		DiscoveryAksClusters,
		DiscoveryAppServiceApps,
		DiscoveryCacheRedis,
		DiscoveryBatchAccounts,
		DiscoveryStorageAccounts,
		DiscoveryKeyVaults,
		DiscoveryManagedHsms,
		DiscoveryIotHubs,
		DiscoverySecurityGroups,
		DiscoveryCosmosDb,
		DiscoveryVirtualNetworks,
		DiscoveryContainerRegistries,
		DiscoveryRecoveryServicesVaults,
		DiscoverySynapseWorkspaces,
		DiscoveryDataFactories,
		DiscoveryFunctionApps,
		DiscoveryApplicationGateways,
		DiscoveryFirewalls,
		DiscoveryContainerApps,
		DiscoveryCognitiveServices,
	}
	require.ElementsMatch(t, expected, Auto)
	require.NotContains(t, Auto, DiscoveryInstancesApi, "virtual machines are opt-in, not part of auto")
}

func TestGetDiscoveryTargets(t *testing.T) {
	cases := []struct {
		name    string
		targets []string
		want    []string
	}{
		{
			name:    "empty defaults to Auto",
			targets: []string{},
			want:    Auto,
		},
		{
			name:    "all",
			targets: []string{"all"},
			want:    All,
		},
		{
			name:    "all with extras",
			targets: []string{"all", "projects", "instances"},
			want:    All,
		},
		{
			name:    "auto",
			targets: []string{"auto"},
			want:    Auto,
		},
		{
			name:    "auto with extras",
			targets: []string{"auto", "cosmosdb", "keyvaults-vaults"},
			want:    append(slices.Clone(Auto), DiscoveryCosmosDb, DiscoveryKeyVaults),
		},
		{
			name:    "explicit targets",
			targets: []string{"cosmosdb", "keyvaults-vaults", "instances"},
			want:    []string{DiscoveryCosmosDb, DiscoveryKeyVaults, DiscoveryInstances},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := &inventory.Config{
				Discover: &inventory.Discovery{
					Targets: tc.targets,
				},
			}
			got := getDiscoveryTargets(config)
			require.ElementsMatch(t, tc.want, got)
		})
	}
}

func TestGetInstancesLabels(t *testing.T) {
	const vmResourceID = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-vm"

	newVM := func(props any) *mqlAzureSubscriptionComputeServiceVm {
		return &mqlAzureSubscriptionComputeServiceVm{
			Id:         plugin.TValue[string]{Data: vmResourceID, State: plugin.StateIsSet},
			Properties: plugin.TValue[any]{Data: props, State: plugin.StateIsSet},
		}
	}

	cases := []struct {
		name string
		vm   *mqlAzureSubscriptionComputeServiceVm
		want map[string]string
	}{
		{
			name: "happy path with all fields",
			vm: newVM(map[string]any{
				"vmId": "abc-123",
				"osProfile": map[string]any{
					"computerName": "host1",
				},
				"storageProfile": map[string]any{
					"osDisk": map[string]any{
						"osType": "Linux",
					},
				},
			}),
			want: map[string]string{
				"azure.mondoo.com/computername":  "host1",
				"azure.mondoo.com/ostype":        "Linux",
				"azure.mondoo.com/resourcegroup": "my-rg",
				"mondoo.com/instance":            "abc-123",
			},
		},
		{
			name: "properties not a map",
			vm:   newVM("not-a-map"),
			want: map[string]string{
				"azure.mondoo.com/resourcegroup": "my-rg",
			},
		},
		{
			name: "properties nil",
			vm:   newVM(nil),
			want: map[string]string{
				"azure.mondoo.com/resourcegroup": "my-rg",
			},
		},
		{
			name: "osProfile present but not a map",
			vm: newVM(map[string]any{
				"osProfile": "oops",
			}),
			want: map[string]string{
				"azure.mondoo.com/resourcegroup": "my-rg",
			},
		},
		{
			name: "computerName missing",
			vm: newVM(map[string]any{
				"osProfile": map[string]any{},
			}),
			want: map[string]string{
				"azure.mondoo.com/resourcegroup": "my-rg",
			},
		},
		{
			name: "computerName not a string",
			vm: newVM(map[string]any{
				"osProfile": map[string]any{
					"computerName": 42,
				},
			}),
			want: map[string]string{
				"azure.mondoo.com/resourcegroup": "my-rg",
			},
		},
		{
			name: "storageProfile not a map",
			vm: newVM(map[string]any{
				"storageProfile": "nope",
			}),
			want: map[string]string{
				"azure.mondoo.com/resourcegroup": "my-rg",
			},
		},
		{
			name: "osDisk not a map",
			vm: newVM(map[string]any{
				"storageProfile": map[string]any{
					"osDisk": 7,
				},
			}),
			want: map[string]string{
				"azure.mondoo.com/resourcegroup": "my-rg",
			},
		},
		{
			name: "osType not a string",
			vm: newVM(map[string]any{
				"storageProfile": map[string]any{
					"osDisk": map[string]any{
						"osType": []string{"Linux"},
					},
				},
			}),
			want: map[string]string{
				"azure.mondoo.com/resourcegroup": "my-rg",
			},
		},
		{
			name: "vmId not a string",
			vm: newVM(map[string]any{
				"vmId": 12345,
			}),
			want: map[string]string{
				"azure.mondoo.com/resourcegroup": "my-rg",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := getInstancesLabels(tc.vm)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestGetInstancesLabels_PropertiesError(t *testing.T) {
	vm := &mqlAzureSubscriptionComputeServiceVm{
		Properties: plugin.TValue[any]{Error: errors.New("boom"), State: plugin.StateIsSet},
	}
	_, err := getInstancesLabels(vm)
	require.Error(t, err)
}

func TestPropagateSubscriptionTagsToAssets(t *testing.T) {
	t.Run("fills missing keys", func(t *testing.T) {
		assets := []*inventory.Asset{{Labels: map[string]string{"a": "1"}}}
		propagateSubscriptionTagsToAssets(assets, map[string]string{"b": "2"})
		require.Equal(t, map[string]string{"a": "1", "b": "2"}, assets[0].Labels)
	})

	t.Run("asset label wins on collision", func(t *testing.T) {
		assets := []*inventory.Asset{{Labels: map[string]string{"env": "dev"}}}
		propagateSubscriptionTagsToAssets(assets, map[string]string{"env": "prod"})
		require.Equal(t, "dev", assets[0].Labels["env"])
	})

	t.Run("nil asset labels are initialized", func(t *testing.T) {
		assets := []*inventory.Asset{{}}
		propagateSubscriptionTagsToAssets(assets, map[string]string{"b": "2"})
		require.Equal(t, map[string]string{"b": "2"}, assets[0].Labels)
	})

	t.Run("empty tags is a no-op", func(t *testing.T) {
		assets := []*inventory.Asset{{Labels: map[string]string{"a": "1"}}}
		propagateSubscriptionTagsToAssets(assets, nil)
		require.Equal(t, map[string]string{"a": "1"}, assets[0].Labels)
	})

	t.Run("nil asset in slice is skipped", func(t *testing.T) {
		assets := []*inventory.Asset{nil, {Labels: map[string]string{}}}
		require.NotPanics(t, func() {
			propagateSubscriptionTagsToAssets(assets, map[string]string{"b": "2"})
		})
		require.Equal(t, map[string]string{"b": "2"}, assets[1].Labels)
	})
}

func TestAssetsForSubscription(t *testing.T) {
	assets := []*inventory.Asset{
		{Name: "a", Labels: map[string]string{SubscriptionLabel: "sub-1"}},
		{Name: "b", Labels: map[string]string{SubscriptionLabel: "sub-2"}},
		{Name: "c", Labels: map[string]string{SubscriptionLabel: "sub-1"}},
		nil,
		{Name: "d", Labels: nil},
	}
	got := assetsForSubscription(assets, "sub-1")
	require.Len(t, got, 2)
	require.Equal(t, "a", got[0].Name)
	require.Equal(t, "c", got[1].Name)
}

func TestSubToAsset_SetsSubscriptionLabel(t *testing.T) {
	asset := subToAsset(subWithConfig{
		sub: subscriptions.Subscription{
			SubscriptionID: to.Ptr("sub-1"),
			DisplayName:    to.Ptr("My Sub"),
			TenantID:       to.Ptr("tenant-1"),
		},
		conf: &inventory.Config{},
	})
	require.Equal(t, "sub-1", asset.Labels[SubscriptionLabel])
}

func TestApplySubscriptionTags_Override(t *testing.T) {
	subs := []subWithConfig{
		{sub: subscriptions.Subscription{SubscriptionID: to.Ptr("sub-1")}},
		{sub: subscriptions.Subscription{SubscriptionID: to.Ptr("sub-2")}},
	}
	assets := []*inventory.Asset{
		{Name: "vm1", Labels: map[string]string{SubscriptionLabel: "sub-1"}},
		{Name: "vm2", Labels: map[string]string{SubscriptionLabel: "sub-2", "env": "dev"}},
		{Name: "orphan", Labels: map[string]string{SubscriptionLabel: "sub-3"}},
	}

	// override wins over each subscription's own tags
	applySubscriptionTags(map[string]string{"env": "prod"}, subs, assets)

	require.Equal(t, "prod", assets[0].Labels["env"]) // filled from the override
	require.Equal(t, "dev", assets[1].Labels["env"])  // asset value wins on collision
	require.NotContains(t, assets[2].Labels, "env")   // sub-3 not in subs list — untouched
}

func TestApplySubscriptionTags_FromListedSubscription(t *testing.T) {
	// no override: tags come straight from the subscription records the list
	// pager already returned, so no extra per-subscription API call is made.
	subs := []subWithConfig{
		{sub: subscriptions.Subscription{
			SubscriptionID: to.Ptr("sub-1"),
			Tags:           map[string]*string{"owner": to.Ptr("alice"), "env": to.Ptr("prod")},
		}},
		{sub: subscriptions.Subscription{SubscriptionID: to.Ptr("sub-2")}}, // no tags
	}
	assets := []*inventory.Asset{
		{Name: "vm1", Labels: map[string]string{SubscriptionLabel: "sub-1"}},
		{Name: "vm2", Labels: map[string]string{SubscriptionLabel: "sub-1", "env": "dev"}},
		{Name: "vm3", Labels: map[string]string{SubscriptionLabel: "sub-2"}},
	}

	applySubscriptionTags(nil, subs, assets)

	require.Equal(t, "alice", assets[0].Labels["owner"]) // filled from subscription tag
	require.Equal(t, "prod", assets[0].Labels["env"])    // filled from subscription tag
	require.Equal(t, "dev", assets[1].Labels["env"])     // asset value wins on collision
	require.Equal(t, "alice", assets[1].Labels["owner"]) // still filled
	require.NotContains(t, assets[2].Labels, "owner")    // sub-2 has no tags
}

// getDiscoveryTargets used to strip "auto" out of the caller's own slice:
// slices.DeleteFunc edits the backing array in place, leaving
// config.Discover.Targets holding [""]. That was invisible while the targets
// were read once per scan. Staged discovery reads them at the tenant level and
// then clones the same config for every subscription, so every subscription
// inherited [""] , matched no target, and discovered nothing -- a tenant scan
// found its subscriptions and not a single resource beneath them.
func TestGetDiscoveryTargetsDoesNotMutateConfig(t *testing.T) {
	tests := [][]string{
		{DiscoveryAuto},
		{DiscoveryAuto, DiscoveryInstancesApi},
		{DiscoveryAll},
		{DiscoveryKeyVaults},
		{},
	}

	for _, targets := range tests {
		t.Run(strings.Join(targets, ","), func(t *testing.T) {
			cfg := &inventory.Config{Discover: &inventory.Discovery{Targets: slices.Clone(targets)}}

			first := getDiscoveryTargets(cfg)
			require.Equal(t, targets, cfg.Discover.Targets,
				"the caller's config must come back untouched")

			// The second read is what a subscription's stage-2 connection does
			// after stage 1 cloned this config for it.
			second := getDiscoveryTargets(cfg)
			require.Equal(t, first, second, "repeated reads must agree")
		})
	}
}

// The clone stage 1 hands each subscription has to resolve to the same targets
// the tenant did, or stage 2 discovers nothing.
func TestGetDiscoveryTargetsSurvivesCloning(t *testing.T) {
	root := &inventory.Config{Discover: &inventory.Discovery{Targets: []string{DiscoveryAuto}}}
	rootTargets := getDiscoveryTargets(root)

	child := root.Clone()
	require.Equal(t, rootTargets, getDiscoveryTargets(child),
		"a subscription must resolve the same targets as the tenant it came from")
	require.Contains(t, getDiscoveryTargets(child), DiscoveryKeyVaults,
		"auto must still expand to the API resource targets after cloning")
}

// The retired Single Server targets are still accepted so an existing inventory
// keeps parsing, but nothing discovers them any more. A target that matches no
// resource is indistinguishable from a successful scan of an empty estate, so
// the warning is the only signal the user gets -- assert it actually fires.
func TestRetiredDiscoveryTargetsWarn(t *testing.T) {
	cases := []struct {
		name        string
		targets     []string
		wantWarn    bool
		wantMatches []string
	}{
		{
			name:        "retired mysql target warns and names its replacement",
			targets:     []string{"mysql-servers"},
			wantWarn:    true,
			wantMatches: []string{"mysql-servers", DiscoveryMySqlFlexibleServers},
		},
		{
			name:        "retired postgres target warns and names its replacement",
			targets:     []string{"postgres-servers"},
			wantWarn:    true,
			wantMatches: []string{"postgres-servers", DiscoveryPostgresFlexibleServers},
		},
		{
			name:     "current targets stay quiet",
			targets:  []string{DiscoveryMySqlFlexibleServers, DiscoveryPostgresFlexibleServers, DiscoveryKeyVaults},
			wantWarn: false,
		},
		{
			name:     "auto stays quiet",
			targets:  []string{DiscoveryAuto},
			wantWarn: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			original := log.Logger
			log.Logger = zerolog.New(&buf)
			defer func() { log.Logger = original }()

			getDiscoveryTargets(&inventory.Config{
				Discover: &inventory.Discovery{Targets: tc.targets},
			})

			out := buf.String()
			if !tc.wantWarn {
				require.NotContains(t, out, "retired")
				return
			}
			require.Contains(t, out, "retired")
			for _, want := range tc.wantMatches {
				require.Contains(t, out, want)
			}
		})
	}
}

// The retired targets must be gone from the lists that drive an unqualified
// scan, or "auto" keeps asking ARM for resource types that cannot exist.
func TestRetiredTargetsAreNotDiscovered(t *testing.T) {
	for retired := range retiredDiscoveryTargets {
		require.NotContains(t, AllAPIResources, retired)
		require.NotContains(t, Auto, retired)
		require.NotContains(t, All, retired)
		for _, spec := range genericDiscoverySpecs {
			require.NotEqual(t, retired, spec.discoveryTarget)
		}
	}
	for _, spec := range genericDiscoverySpecs {
		require.NotEqual(t, "Microsoft.DBforMySQL/servers", spec.armType)
		require.NotEqual(t, "Microsoft.DBforPostgreSQL/servers", spec.armType)
	}
}
