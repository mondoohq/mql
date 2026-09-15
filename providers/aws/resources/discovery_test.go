// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"maps"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
)

func TestAllResolvedResources(t *testing.T) {
	expected := []string{
		DiscoveryAccounts,
		DiscoveryS3Buckets,
		DiscoveryEKSClusters,
		DiscoveryCloudtrailTrails,
		DiscoveryRdsDbInstances,
		DiscoveryRdsDbClusters,
		DiscoveryVPCs,
		DiscoverySecurityGroups,
		DiscoveryIAMUsers,
		DiscoveryIAMGroups,
		DiscoveryCloudwatchLoggroups,
		DiscoveryLambdaFunctions,
		DiscoveryDynamoDBTables,
		DiscoveryDynamoDBGlobalTables,
		DiscoveryRedshiftClusters,
		DiscoveryRdsSnapshots,
		DiscoveryVolumes,
		DiscoverySnapshots,
		DiscoveryEFSFilesystems,
		DiscoveryAPIGatewayRestAPIs,
		DiscoveryELBLoadBalancers,
		DiscoveryESDomains,
		DiscoveryOpenSearchDomains,
		DiscoveryKMSKeys,
		DiscoverySagemakerNotebookInstances,
		DiscoverySagemakerProcessingJobs,
		DiscoverySagemakerTrainingJobs,
		DiscoverySagemakerDomains,
		DiscoverySagemakerModels,
		DiscoverySecretsManagerSecrets,
		DiscoveryElasticacheClusters,
		DiscoveryCloudfrontDistributions,
		DiscoveryNeptuneClusters,
		DiscoveryEMRClusters,
		DiscoveryDocumentDBClusters,
		DiscoveryMskClusters,
		DiscoveryMqBrokers,
		DiscoveryEcsTaskDefinitions,
		DiscoveryRoute53HostedZones,
		DiscoveryEcrRepositories,
		DiscoveryMemorydbClusters,
		DiscoveryCodebuildProjects,
		DiscoveryCognitoUserPools,
		DiscoveryTransferServers,
		DiscoveryAPIGatewayV2APIs,
		DiscoveryAthenaWorkgroups,
		DiscoveryAppStreamFleets,
		DiscoveryBatchJobDefinitions,
		DiscoveryDirectoryServiceDirectories,
		DiscoveryDocumentDBInstances,
		DiscoverySnsTopics,
		DiscoverySqsQueues,
		DiscoveryInstances,
		DiscoverySSMInstances,
		DiscoveryECR,
		DiscoveryECS,
	}
	require.ElementsMatch(t, expected, All)
}

func TestAutoResolvedResources(t *testing.T) {
	expected := []string{
		DiscoveryAccounts,
		DiscoveryS3Buckets,
		DiscoveryEKSClusters,
		DiscoveryCloudtrailTrails,
		DiscoveryRdsDbInstances,
		DiscoveryRdsDbClusters,
		DiscoveryVPCs,
		DiscoverySecurityGroups,
		DiscoveryIAMUsers,
		DiscoveryIAMGroups,
		DiscoveryCloudwatchLoggroups,
		DiscoveryLambdaFunctions,
		DiscoveryDynamoDBTables,
		DiscoveryDynamoDBGlobalTables,
		DiscoveryRedshiftClusters,
		DiscoveryRdsSnapshots,
		DiscoveryVolumes,
		DiscoverySnapshots,
		DiscoveryEFSFilesystems,
		DiscoveryAPIGatewayRestAPIs,
		DiscoveryELBLoadBalancers,
		DiscoveryESDomains,
		DiscoveryOpenSearchDomains,
		DiscoveryKMSKeys,
		DiscoverySagemakerNotebookInstances,
		DiscoverySagemakerProcessingJobs,
		DiscoverySagemakerTrainingJobs,
		DiscoverySagemakerDomains,
		DiscoverySagemakerModels,
		DiscoverySecretsManagerSecrets,
		DiscoveryElasticacheClusters,
		DiscoveryCloudfrontDistributions,
		DiscoveryNeptuneClusters,
		DiscoveryEMRClusters,
		DiscoveryDocumentDBClusters,
		DiscoveryMskClusters,
		DiscoveryMqBrokers,
		DiscoveryEcsTaskDefinitions,
		DiscoveryRoute53HostedZones,
		DiscoveryEcrRepositories,
		DiscoveryMemorydbClusters,
		DiscoveryCodebuildProjects,
		DiscoveryCognitoUserPools,
		DiscoveryTransferServers,
		DiscoveryAPIGatewayV2APIs,
		DiscoveryAthenaWorkgroups,
		DiscoveryAppStreamFleets,
		DiscoveryBatchJobDefinitions,
		DiscoveryDirectoryServiceDirectories,
		DiscoveryDocumentDBInstances,
		DiscoverySnsTopics,
		DiscoverySqsQueues,
	}
	require.ElementsMatch(t, expected, Auto)
}

func TestAddConnInfoToEc2Instances(t *testing.T) {
	info := instanceInfo{}
	a := &inventory.Asset{}
	addMondooLabels(info, a)
	require.Equal(t, map[string]string{"mondoo.com/instance-id": "", "mondoo.com/instance-type": "", "mondoo.com/parent-id": "", "mondoo.com/platform": "", "mondoo.com/region": ""}, a.Labels)
	info = instanceInfo{
		region:          "us-west-1",
		platformDetails: "windows",
		instanceType:    "t4g.medium",
		accountId:       "00000000000000",
		instanceId:      "i-9049034093403",
		launchTime:      nil,
	}
	a = &inventory.Asset{}
	expectedLabels := map[string]string{"mondoo.com/instance-id": "i-9049034093403", "mondoo.com/instance-type": "t4g.medium", "mondoo.com/parent-id": "00000000000000", "mondoo.com/platform": "windows", "mondoo.com/region": "us-west-1"}
	addMondooLabels(info, a)
	require.Equal(t, expectedLabels, a.Labels)
	now := time.Now()
	info.launchTime = &now
	addMondooLabels(info, a)
	require.NotNil(t, expectedLabels[MondooLaunchTimeLabelKey])
	info.image = aws.String("test")
	addMondooLabels(info, a)
	require.NotNil(t, expectedLabels[MondooImageLabelKey])
	info.instanceTags = nil
	addMondooLabels(info, a)
	info.instanceTags = map[string]string{"testing-key": "testing-val"}
	addMondooLabels(info, a)
	require.Equal(t, a.Labels["testing-key"], "testing-val")
}

// configBuilder provides a fluent API for constructing test configs
type configBuilder struct {
	cfg *inventory.Config
}

func newTestConfig() *configBuilder {
	return &configBuilder{
		cfg: &inventory.Config{
			Type:    "aws",
			Options: map[string]string{},
			Discover: &inventory.Discovery{
				Targets: []string{},
				Filter:  map[string]string{},
			},
		},
	}
}

func (b *configBuilder) withId(id uint32) *configBuilder {
	b.cfg.Id = id
	return b
}

func (b *configBuilder) withOption(key, value string) *configBuilder {
	b.cfg.Options[key] = value
	return b
}

func (b *configBuilder) withTargets(targets ...string) *configBuilder {
	b.cfg.Discover.Targets = targets
	return b
}

func (b *configBuilder) withRegions(regions string) *configBuilder {
	b.cfg.Discover.Filter["regions"] = regions
	return b
}

func (b *configBuilder) withExcludeRegions(regions string) *configBuilder {
	b.cfg.Discover.Filter["exclude:regions"] = regions
	return b
}

func (b *configBuilder) withTag(key, value string) *configBuilder {
	b.cfg.Discover.Filter["tag:"+key] = value
	return b
}

func (b *configBuilder) withFilter(key, value string) *configBuilder {
	b.cfg.Discover.Filter[key] = value
	return b
}

func (b *configBuilder) build() *inventory.Config {
	return b.cfg
}

// assertFiltersPreserved verifies all parent filters exist in child with same values
func assertFiltersPreserved(t *testing.T, parent, child *inventory.Config) {
	t.Helper()
	for key, val := range parent.Discover.Filter {
		childVal, exists := child.Discover.Filter[key]
		require.True(t, exists, "filter %q missing in child", key)
		require.Equal(t, val, childVal, "filter %q value mismatch", key)
	}
	require.Equal(t, len(parent.Discover.Filter), len(child.Discover.Filter),
		"child has different number of filters than parent")
}

// assertFiltersEmpty verifies child has no filters
func assertFiltersEmpty(t *testing.T, child *inventory.Config) {
	t.Helper()
	require.Empty(t, child.Discover.Filter, "expected empty filters in child")
}

// assertTargetsEmpty verifies child has no discovery targets
func assertTargetsEmpty(t *testing.T, child *inventory.Config) {
	t.Helper()
	require.Empty(t, child.Discover.Targets, "expected empty targets in child")
}

// assertIsolation verifies modifying child doesn't affect parent
func assertIsolation(t *testing.T, parent, child *inventory.Config) {
	t.Helper()
	// Store original parent values
	origRegions := parent.Discover.Filter["regions"]
	origOptions := make(map[string]string)
	maps.Copy(origOptions, parent.Options)

	// Modify child
	child.Discover.Filter["regions"] = "modified-region"
	child.Options["modified-key"] = "modified-value"

	// Parent should be unchanged
	require.Equal(t, origRegions, parent.Discover.Filter["regions"], "parent regions modified")
	require.Equal(t, origOptions, parent.Options, "parent options modified")
}

// cloneForChild creates a child config using the production pattern
func cloneForChild(parent *inventory.Config) *inventory.Config {
	return parent.Clone(
		inventory.WithoutDiscovery(),
		inventory.WithParentConnectionId(parent.Id),
		inventory.WithFilters(),
	)
}

// cloneForChildBroken simulates forgetting WithFilters (bug scenario)
func cloneForChildBroken(parent *inventory.Config) *inventory.Config {
	return parent.Clone(
		inventory.WithoutDiscovery(),
		inventory.WithParentConnectionId(parent.Id),
	)
}

func TestDiscoveryAndFilterPropagation(t *testing.T) {
	t.Run("clone options behavior", func(t *testing.T) {
		cases := []struct {
			name           string
			cloneOpts      []inventory.CloneOption
			expectFilters  bool
			expectTargets  bool
			expectParentId bool
		}{
			{
				name: "WithFilters only",
				cloneOpts: []inventory.CloneOption{
					inventory.WithFilters(),
				},
				expectFilters:  true,
				expectTargets:  true, // targets preserved without WithoutDiscovery
				expectParentId: false,
			},
			{
				name: "WithoutDiscovery only",
				cloneOpts: []inventory.CloneOption{
					inventory.WithoutDiscovery(),
				},
				expectFilters:  false, // filters lost without WithFilters
				expectTargets:  false,
				expectParentId: false,
			},
			{
				name: "WithoutDiscovery + WithFilters (production pattern)",
				cloneOpts: []inventory.CloneOption{
					inventory.WithoutDiscovery(),
					inventory.WithFilters(),
				},
				expectFilters:  true,
				expectTargets:  false,
				expectParentId: false,
			},
			{
				name: "full production pattern",
				cloneOpts: []inventory.CloneOption{
					inventory.WithoutDiscovery(),
					inventory.WithParentConnectionId(1),
					inventory.WithFilters(),
				},
				expectFilters:  true,
				expectTargets:  false,
				expectParentId: true,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				parent := newTestConfig().
					withId(1).
					withTargets("accounts", "s3-buckets").
					withRegions("us-east-1").
					withTag("Env", "prod").
					build()

				child := parent.Clone(tc.cloneOpts...)

				if tc.expectFilters {
					assertFiltersPreserved(t, parent, child)
				} else {
					assertFiltersEmpty(t, child)
				}

				if tc.expectTargets {
					require.ElementsMatch(t, parent.Discover.Targets, child.Discover.Targets)
				} else {
					assertTargetsEmpty(t, child)
				}

				if tc.expectParentId {
					require.Equal(t, uint32(1), child.ParentConnectionId)
				} else {
					require.Equal(t, uint32(0), child.ParentConnectionId)
				}
			})
		}
	})

	t.Run("filter propagation with all filter types", func(t *testing.T) {
		filterCases := []struct {
			key   string
			value string
		}{
			{"regions", "us-east-1,us-west-2,eu-central-1"},
			{"exclude:regions", "ap-southeast-1,ap-northeast-1"},
			{"tag:Environment", "production,staging"},
			{"tag:Team", "platform"},
			{"exclude:tag:Temporary", "true"},
			{"ec2:instance-ids", "i-123,i-456"},
			{"ecr:tags", "latest,stable"},
		}

		parent := newTestConfig().withId(1).withTargets("accounts").build()
		for _, fc := range filterCases {
			parent.Discover.Filter[fc.key] = fc.value
		}

		child := cloneForChild(parent)

		// Verify each filter type propagated
		for _, fc := range filterCases {
			require.Equal(t, fc.value, child.Discover.Filter[fc.key],
				"filter %q not propagated correctly", fc.key)
		}
		assertTargetsEmpty(t, child)
	})

	t.Run("discovery targets resolution", func(t *testing.T) {
		cases := []struct {
			name            string
			inputTargets    []string
			expectedTargets []string
		}{
			{"empty returns empty (ParseCLI sets default)", []string{}, []string{}},
			{"auto keyword", []string{"auto"}, Auto},
			{"all keyword", []string{"all"}, All},
			{"resources keyword", []string{"resources"}, AllAPIResources},
			{"explicit single", []string{"s3-buckets"}, []string{DiscoveryS3Buckets}},
			{
				"explicit multiple",
				[]string{"s3-buckets", "instances", "iam-users"},
				[]string{DiscoveryS3Buckets, DiscoveryInstances, DiscoveryIAMUsers},
			},
			{"auto takes precedence", []string{"auto", "s3-buckets"}, Auto},
			{"all takes precedence", []string{"all", "s3-buckets"}, All},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				parent := newTestConfig().
					withTargets(tc.inputTargets...).
					withRegions("us-east-1").
					build()

				// Verify parent targets resolve correctly
				resolved := getDiscoveryTargets(parent)
				require.ElementsMatch(t, tc.expectedTargets, resolved)

				// Verify child always has empty targets after clone
				child := cloneForChild(parent)
				assertTargetsEmpty(t, child)
				// But filters preserved
				require.Equal(t, "us-east-1", child.Discover.Filter["regions"])
			})
		}
	})

	t.Run("multi-level hierarchy propagation", func(t *testing.T) {
		levels := 4 // org -> account -> vpc -> instance
		configs := make([]*inventory.Config, levels)

		// Build root config
		configs[0] = newTestConfig().
			withId(100).
			withTargets("accounts").
			withRegions("us-east-1,eu-west-1").
			withTag("Environment", "prod").
			build()

		// Clone through each level
		for i := 1; i < levels; i++ {
			configs[i] = cloneForChild(configs[i-1])
			configs[i].Id = uint32(100 + i) // Simulate runtime ID assignment
		}

		// Verify chain integrity
		for i := 1; i < levels; i++ {
			// Parent ID points to previous level
			require.Equal(t, configs[i-1].Id, configs[i].ParentConnectionId,
				"level %d should point to level %d", i, i-1)
			// Filters propagated through all levels
			assertFiltersPreserved(t, configs[0], configs[i])
			// Targets cleared at each child level
			assertTargetsEmpty(t, configs[i])
		}

		// Root targets unchanged
		require.ElementsMatch(t, []string{"accounts"}, configs[0].Discover.Targets)
	})

	t.Run("isolation between parent and child", func(t *testing.T) {
		parent := newTestConfig().
			withId(1).
			withOption("profile", "org-master").
			withTargets("accounts").
			withRegions("us-east-1,us-west-2").
			withTag("Team", "platform").
			build()

		child := cloneForChild(parent)
		assertIsolation(t, parent, child)
	})

	t.Run("broken vs correct propagation comparison", func(t *testing.T) {
		parent := newTestConfig().
			withId(1).
			withTargets("accounts").
			withRegions("us-east-1").
			withExcludeRegions("eu-central-1").
			withTag("Environment", "prod").
			build()

		broken := cloneForChildBroken(parent)
		correct := cloneForChild(parent)

		// Broken: no filters
		assertFiltersEmpty(t, broken)
		assertTargetsEmpty(t, broken)

		// Correct: filters preserved
		assertFiltersPreserved(t, parent, correct)
		assertTargetsEmpty(t, correct)
	})
}

func TestGetDiscoveryTargets(t *testing.T) {
	cases := []struct {
		name    string
		targets []string
		want    []string
	}{
		{
			name:    "empty returns empty (ParseCLI sets default)",
			targets: []string{},
			want:    []string{},
		},
		{
			name:    "all",
			targets: []string{"all"},
			want:    All,
		},
		{
			name:    "auto",
			targets: []string{"auto"},
			want:    Auto,
		},
		{
			name:    "resources",
			targets: []string{"resources"},
			want:    AllAPIResources,
		},
		{
			name:    "auto and resources",
			targets: []string{"auto", "resources"},
			want:    Auto,
		},
		{
			name:    "all and resources",
			targets: []string{"all", "resources"},
			want:    All,
		},
		{
			name:    "all, auto and resources",
			targets: []string{"all", "resources"},
			want:    All,
		},
		{
			name:    "random",
			targets: []string{"s3-buckets", "iam-users", "instances"},
			want:    []string{DiscoveryS3Buckets, DiscoveryIAMUsers, DiscoveryInstances},
		},
		{
			name:    "duplicates",
			targets: []string{"auto", "s3-buckets", "iam-users", "s3-buckets", "auto"},
			want:    Auto,
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

// TestDiscoveryDefaultBehavior documents the expected discovery flow:
//
//  1. ParseCLI (in provider.go): When no --discover flag is provided, it sets
//     targets to ["auto"]. This ensures the parent connection always has explicit targets.
//
//  2. getDiscoveryTargets: Expands "auto" to the Auto list. Does NOT provide a
//     fallback for empty targets - that's ParseCLI's responsibility.
//
//  3. Child connections: Created with WithoutDiscovery() which sets Discover to
//     an empty struct (targets = nil/empty). This prevents re-discovery.
//
// 4. Service.discover(): Checks len(targets) == 0 to skip discovery for children.
func TestDiscoveryDefaultBehavior(t *testing.T) {
	t.Run("ParseCLI sets auto target - simulated parent connection", func(t *testing.T) {
		// Simulate what ParseCLI does: when no --discover flag, set "auto"
		parentConfig := &inventory.Config{
			Discover: &inventory.Discovery{
				Targets: []string{DiscoveryAuto}, // ParseCLI sets this
			},
		}

		// getDiscoveryTargets should expand "auto" to the full Auto list
		resolved := getDiscoveryTargets(parentConfig)
		require.ElementsMatch(t, Auto, resolved,
			"parent with 'auto' target should resolve to full Auto list")
		require.NotEmpty(t, resolved, "parent should have discovery targets")
	})

	t.Run("child connection has no targets - discovery skipped", func(t *testing.T) {
		// Simulate parent with targets set by ParseCLI
		parentConfig := &inventory.Config{
			Id: 1,
			Discover: &inventory.Discovery{
				Targets: []string{DiscoveryAuto},
				Filter:  map[string]string{"regions": "us-east-1"},
			},
		}

		// Simulate child creation with WithoutDiscovery() + WithFilters()
		childConfig := parentConfig.Clone(
			inventory.WithoutDiscovery(),
			inventory.WithParentConnectionId(parentConfig.Id),
			inventory.WithFilters(),
		)

		// Child should have empty targets (discovery disabled)
		childResolved := getDiscoveryTargets(childConfig)
		require.Empty(t, childResolved,
			"child connection should have empty targets (no discovery)")

		// But filters should be preserved
		require.Equal(t, "us-east-1", childConfig.Discover.Filter["regions"],
			"child should preserve filters from parent")
	})

	t.Run("explicit targets are preserved through flow", func(t *testing.T) {
		// User explicitly specifies --discover=s3-buckets,iam-users
		parentConfig := &inventory.Config{
			Discover: &inventory.Discovery{
				Targets: []string{"s3-buckets", "iam-users"},
			},
		}

		resolved := getDiscoveryTargets(parentConfig)
		require.ElementsMatch(t, []string{DiscoveryS3Buckets, DiscoveryIAMUsers}, resolved,
			"explicit targets should be preserved")

		// Child still gets no targets
		childConfig := parentConfig.Clone(inventory.WithoutDiscovery())
		childResolved := getDiscoveryTargets(childConfig)
		require.Empty(t, childResolved,
			"child should have no targets regardless of parent's explicit targets")
	})
}

func TestMergeAccountTagsIntoLabels(t *testing.T) {
	t.Run("asset label wins on collision", func(t *testing.T) {
		labels := map[string]string{"Environment": "prod"}
		accountTags := map[string]string{"Environment": "staging", "Owner": "team-a"}

		got := mergeAccountTagsIntoLabels(labels, accountTags)

		require.Equal(t, "prod", got["Environment"])
		require.Equal(t, "team-a", got["Owner"])
	})

	t.Run("nil labels initialized", func(t *testing.T) {
		accountTags := map[string]string{"Owner": "team-a"}

		got := mergeAccountTagsIntoLabels(nil, accountTags)

		require.Equal(t, map[string]string{"Owner": "team-a"}, got)
	})

	t.Run("empty account tags is a no-op", func(t *testing.T) {
		labels := map[string]string{"Environment": "prod"}

		got := mergeAccountTagsIntoLabels(labels, map[string]string{})

		require.Equal(t, map[string]string{"Environment": "prod"}, got)
	})

	t.Run("nil account tags is a no-op", func(t *testing.T) {
		labels := map[string]string{"Environment": "prod"}

		got := mergeAccountTagsIntoLabels(labels, nil)

		require.Equal(t, map[string]string{"Environment": "prod"}, got)
	})

	t.Run("fills gaps without touching existing keys", func(t *testing.T) {
		labels := map[string]string{"Name": "web-01"}
		accountTags := map[string]string{"Owner": "team-a", "CostCenter": "cc-42"}

		got := mergeAccountTagsIntoLabels(labels, accountTags)

		require.Equal(t, "web-01", got["Name"])
		require.Equal(t, "team-a", got["Owner"])
		require.Equal(t, "cc-42", got["CostCenter"])
	})
}

func TestIsSiblingOrgAccountAsset(t *testing.T) {
	primaryAccountId := "111111111111"

	t.Run("primary account asset returns false", func(t *testing.T) {
		a := &inventory.Asset{
			Platform:    &inventory.Platform{Name: "aws"},
			PlatformIds: []string{"//platformid.api.mondoo.app/runtime/aws/accounts/111111111111"},
		}
		require.False(t, isSiblingOrgAccountAsset(a, primaryAccountId))
	})

	t.Run("sibling account asset returns true", func(t *testing.T) {
		a := &inventory.Asset{
			Platform:    &inventory.Platform{Name: "aws"},
			PlatformIds: []string{"//platformid.api.mondoo.app/runtime/aws/accounts/222222222222"},
		}
		require.True(t, isSiblingOrgAccountAsset(a, primaryAccountId))
	})

	t.Run("non-account asset returns false", func(t *testing.T) {
		a := &inventory.Asset{
			Platform:    &inventory.Platform{Name: "aws-ec2-instance"},
			PlatformIds: []string{"//platformid.api.mondoo.app/runtime/aws/accounts/222222222222/regions/us-east-1/instances/i-abc"},
		}
		require.False(t, isSiblingOrgAccountAsset(a, primaryAccountId))
	})

	t.Run("nil asset returns false", func(t *testing.T) {
		require.False(t, isSiblingOrgAccountAsset(nil, primaryAccountId))
	})

	t.Run("asset with nil platform returns false", func(t *testing.T) {
		a := &inventory.Asset{
			PlatformIds: []string{"//platformid.api.mondoo.app/runtime/aws/accounts/222222222222"},
		}
		require.False(t, isSiblingOrgAccountAsset(a, primaryAccountId))
	})
}

func TestApplyAccountTagsToAssets(t *testing.T) {
	primaryAccountId := "111111111111"
	accountTags := map[string]string{
		"Owner":       "team-a",
		"CostCenter":  "cc-42",
		"Environment": "staging",
	}

	primaryAccount := &inventory.Asset{
		Name:        "primary",
		Platform:    &inventory.Platform{Name: "aws"},
		PlatformIds: []string{"//platformid.api.mondoo.app/runtime/aws/accounts/111111111111"},
		Labels:      map[string]string{},
	}
	siblingAccount := &inventory.Asset{
		Name:        "sibling",
		Platform:    &inventory.Platform{Name: "aws"},
		PlatformIds: []string{"//platformid.api.mondoo.app/runtime/aws/accounts/222222222222"},
		Labels:      map[string]string{"OtherAccountTag": "x"},
	}
	ec2Asset := &inventory.Asset{
		Name:        "web-01",
		Platform:    &inventory.Platform{Name: "aws-ec2-instance"},
		PlatformIds: []string{"//platformid.api.mondoo.app/runtime/aws/accounts/111111111111/regions/us-east-1/instances/i-abc"},
		Labels:      map[string]string{"Environment": "prod", "Name": "web-01"},
	}
	assets := []*inventory.Asset{primaryAccount, siblingAccount, ec2Asset}

	applyAccountTagsToAssets(assets, accountTags, primaryAccountId)

	require.Equal(t, "team-a", primaryAccount.Labels["Owner"])
	require.Equal(t, "cc-42", primaryAccount.Labels["CostCenter"])
	require.Equal(t, "staging", primaryAccount.Labels["Environment"])

	require.Equal(t, map[string]string{"OtherAccountTag": "x"}, siblingAccount.Labels)

	require.Equal(t, "prod", ec2Asset.Labels["Environment"])
	require.Equal(t, "web-01", ec2Asset.Labels["Name"])
	require.Equal(t, "team-a", ec2Asset.Labels["Owner"])
	require.Equal(t, "cc-42", ec2Asset.Labels["CostCenter"])
}
