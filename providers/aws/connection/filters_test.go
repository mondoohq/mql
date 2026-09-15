// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// withCapturedLog swaps the global logger for a buffer so tests can assert on
// deprecation warnings.
func withCapturedLog(t *testing.T, f func()) string {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Logger
	log.Logger = zerolog.New(&buf)
	defer func() { log.Logger = orig }()
	f()
	return buf.String()
}

func TestDeprecatedEc2TagOpts(t *testing.T) {
	t.Run("ec2:tag: still applies and warns", func(t *testing.T) {
		var d DiscoveryFilters
		out := withCapturedLog(t, func() {
			d = DiscoveryFiltersFromOpts(map[string]string{"ec2:tag:env": "prod"})
		})
		require.Equal(t, map[string]string{"env": "prod"}, d.General.Tags)
		require.Contains(t, out, "deprecated AWS discovery filter")
		require.Contains(t, out, `"option":"ec2:tag:"`)
		require.Contains(t, out, `"use":"tag:"`)
	})

	t.Run("ec2:exclude:tag: still applies and warns", func(t *testing.T) {
		var d DiscoveryFilters
		out := withCapturedLog(t, func() {
			d = DiscoveryFiltersFromOpts(map[string]string{"ec2:exclude:tag:env": "dev"})
		})
		require.Equal(t, map[string]string{"env": "dev"}, d.General.ExcludeTags)
		require.Contains(t, out, `"option":"ec2:exclude:tag:"`)
		require.Contains(t, out, `"use":"exclude:tag:"`)
	})

	t.Run("a key set by both keeps the replacement and warns about the dropped value", func(t *testing.T) {
		var d DiscoveryFilters
		out := withCapturedLog(t, func() {
			d = DiscoveryFiltersFromOpts(map[string]string{
				"tag:env":     "prod",
				"ec2:tag:env": "staging",
			})
		})
		require.Equal(t, map[string]string{"env": "prod"}, d.General.Tags)
		require.Contains(t, out, "the deprecated value is ignored")
		require.Contains(t, out, `"ignored":"staging"`)
		require.Contains(t, out, `"using":"prod"`)
	})

	t.Run("a key set by both with the same value does not warn about a dropped value", func(t *testing.T) {
		out := withCapturedLog(t, func() {
			DiscoveryFiltersFromOpts(map[string]string{
				"tag:env":     "prod",
				"ec2:tag:env": "prod",
			})
		})
		require.Contains(t, out, "deprecated AWS discovery filter")
		require.NotContains(t, out, "the deprecated value is ignored")
	})

	t.Run("no deprecated opts means no warning", func(t *testing.T) {
		out := withCapturedLog(t, func() {
			DiscoveryFiltersFromOpts(map[string]string{"tag:env": "prod"})
		})
		require.Empty(t, out)
	})
}

func TestToServerSideEc2Filters(t *testing.T) {
	t.Run("correctly converts include and exclude tags to AWS SDK filters", func(t *testing.T) {
		filters := DiscoveryFilters{
			General: GeneralDiscoveryFilters{
				Tags: map[string]string{},
				// ignored
				ExcludeTags: map[string]string{
					"cost-center": "cc1,cc2",
				},
			},
		}

		sdkFilters := filters.General.ToServerSideEc2Filters()
		require.Empty(t, sdkFilters)
	})

	t.Run("correctly converts include and exclude tags to AWS SDK filters", func(t *testing.T) {
		filters := DiscoveryFilters{
			General: GeneralDiscoveryFilters{
				Tags: map[string]string{
					"env":  "prod,staging",
					"team": "alpha",
				},
				// ignored
				ExcludeTags: map[string]string{
					"cost-center": "cc1,cc2",
				},
			},
		}
		sdkFilters := filters.General.ToServerSideEc2Filters()
		expectedFilters := []ec2types.Filter{
			{
				Name:   aws.String("tag:env"),
				Values: []string{"prod", "staging"},
			},
			{
				Name:   aws.String("tag:team"),
				Values: []string{"alpha"},
			},
		}
		require.ElementsMatch(t, expectedFilters, sdkFilters)
	})
}

func TestMatchesIncludeTags(t *testing.T) {
	t.Run("no include tags matches", func(t *testing.T) {
		filters := GeneralDiscoveryFilters{
			Tags: map[string]string{},
		}
		resourceTags := map[string]string{
			"any-key": "any-value",
		}
		require.True(t, filters.MatchesIncludeTags(resourceTags))
	})

	t.Run("include tags do not match", func(t *testing.T) {
		filters := GeneralDiscoveryFilters{
			Tags: map[string]string{
				"tag1": "value1,value11",
				"tag2": "value2",
			},
		}
		resourceTags := map[string]string{
			"tag1": "value3",
		}
		require.False(t, filters.MatchesIncludeTags(resourceTags))
	})

	t.Run("include tags match", func(t *testing.T) {
		filters := GeneralDiscoveryFilters{
			Tags: map[string]string{
				"tag1": "value1,value11",
				"tag2": "value2",
			},
		}
		resourceTags := map[string]string{
			"tag1": "value11",
		}
		require.True(t, filters.MatchesIncludeTags(resourceTags))
	})
}

// A resource whose tag read failed is left out of the pre-fetched map, so the
// lister evaluates it against a nil map rather than an empty one. Callers depend
// on those being indistinguishable here: it is what lets a failed tag fetch stay
// absent (so the tags field can still report null) without changing which
// resources the filter selects.
func TestTagFiltersReadNilLikeAnEmptyMap(t *testing.T) {
	filters := GeneralDiscoveryFilters{
		Tags:        map[string]string{"env": "prod"},
		ExcludeTags: map[string]string{"tier": "scratch"},
	}

	require.Equal(t,
		filters.MatchesIncludeTags(map[string]string{}),
		filters.MatchesIncludeTags(nil),
		"a nil tag map must include exactly like an empty one")
	require.Equal(t,
		filters.MatchesExcludeTags(map[string]string{}),
		filters.MatchesExcludeTags(nil),
		"a nil tag map must exclude exactly like an empty one")
	require.Equal(t,
		filters.IsFilteredOutByTags(map[string]string{}),
		filters.IsFilteredOutByTags(nil))

	// and with no filters configured at all, both are kept
	var none GeneralDiscoveryFilters
	require.False(t, none.IsFilteredOutByTags(nil))
	require.False(t, none.IsFilteredOutByTags(map[string]string{}))
}

func TestMatchesExcludeTags(t *testing.T) {
	t.Run("no exclude tags does not match", func(t *testing.T) {
		filters := GeneralDiscoveryFilters{
			ExcludeTags: map[string]string{},
		}
		resourceTags := map[string]string{
			"any-key": "any-value",
		}
		require.False(t, filters.MatchesExcludeTags(resourceTags))
	})

	t.Run("exclude tags do not match", func(t *testing.T) {
		filters := GeneralDiscoveryFilters{
			ExcludeTags: map[string]string{
				"tag1": "value1,value11",
				"tag2": "value2",
			},
		}
		resourceTags := map[string]string{
			"tag1": "value3",
		}
		require.False(t, filters.MatchesExcludeTags(resourceTags))
	})

	t.Run("exclude tags match", func(t *testing.T) {
		filters := GeneralDiscoveryFilters{
			ExcludeTags: map[string]string{
				"tag1": "value1,value11",
				"tag2": "value2",
			},
		}
		resourceTags := map[string]string{
			"tag1": "value11",
		}
		require.True(t, filters.MatchesExcludeTags(resourceTags))
	})
}

func TestMatchesExcludeInstanceIds(t *testing.T) {
	t.Run("nil instanceId is not excluded", func(t *testing.T) {
		filters := Ec2DiscoveryFilters{
			ExcludeInstanceIds: []string{"i-1234567890abcdef0"},
		}
		require.False(t, filters.MatchesExcludeInstanceIds(nil))
	})

	t.Run("instanceId is not excluded", func(t *testing.T) {
		filters := Ec2DiscoveryFilters{
			ExcludeInstanceIds: []string{"i-1234567890abcdef0"},
		}
		require.False(t, filters.MatchesExcludeInstanceIds(aws.String("i-123456789notmatched")))
	})

	t.Run("instanceId is excluded", func(t *testing.T) {
		filters := Ec2DiscoveryFilters{
			ExcludeInstanceIds: []string{"i-1234567890abcdef0"},
		}
		require.True(t, filters.MatchesExcludeInstanceIds(aws.String("i-1234567890abcdef0")))
	})
}

func TestEcsMatchesOnlyRunningContainers(t *testing.T) {
	t.Run("OnlyRunningContainers is false, any container state matches", func(t *testing.T) {
		filters := EcsDiscoveryFilters{
			OnlyRunningContainers: false,
		}
		require.True(t, filters.MatchesOnlyRunningContainers("RUNNING"))
		require.True(t, filters.MatchesOnlyRunningContainers("STOPPED"))
		require.True(t, filters.MatchesOnlyRunningContainers("PENDING"))
	})

	t.Run("OnlyRunningContainers is true, only RUNNING container state matches", func(t *testing.T) {
		filters := EcsDiscoveryFilters{
			OnlyRunningContainers: true,
		}
		require.True(t, filters.MatchesOnlyRunningContainers("RUNNING"))
		require.False(t, filters.MatchesOnlyRunningContainers("STOPPED"))
		require.False(t, filters.MatchesOnlyRunningContainers("PENDING"))
	})
}

func TestEcrMatchesIncludeTags(t *testing.T) {
	t.Run("no include tags matches", func(t *testing.T) {
		filters := EcrDiscoveryFilters{
			Tags: []string{},
		}
		resourceTags := []string{"tag1", "tag2"}
		require.True(t, filters.MatchesIncludeTags(resourceTags))
	})

	t.Run("include tags do not match", func(t *testing.T) {
		filters := EcrDiscoveryFilters{
			Tags: []string{"tag3", "tag4"},
		}
		resourceTags := []string{"tag1", "tag2"}
		require.False(t, filters.MatchesIncludeTags(resourceTags))
	})

	t.Run("include tags match", func(t *testing.T) {
		filters := EcrDiscoveryFilters{
			Tags: []string{"tag1", "tag3"},
		}
		resourceTags := []string{"tag1", "tag2"}
		require.True(t, filters.MatchesIncludeTags(resourceTags))
	})
}

func TestEcrMatchesExcludeTags(t *testing.T) {
	t.Run("no exclude tags does not match", func(t *testing.T) {
		filters := EcrDiscoveryFilters{
			ExcludeTags: []string{},
		}
		resourceTags := []string{"tag1", "tag2"}
		require.False(t, filters.MatchesExcludeTags(resourceTags))
	})

	t.Run("exclude tags do not match", func(t *testing.T) {
		filters := EcrDiscoveryFilters{
			ExcludeTags: []string{"tag3", "tag4"},
		}
		resourceTags := []string{"tag1", "tag2"}
		require.False(t, filters.MatchesExcludeTags(resourceTags))
	})

	t.Run("exclude tags match", func(t *testing.T) {
		filters := EcrDiscoveryFilters{
			ExcludeTags: []string{"tag1", "tag3"},
		}
		resourceTags := []string{"tag1", "tag2"}
		require.True(t, filters.MatchesExcludeTags(resourceTags))
	})
}

func TestS3IsFilteredOut(t *testing.T) {
	t.Run("no filters keeps every bucket", func(t *testing.T) {
		filters := S3DiscoveryFilters{}
		require.False(t, filters.IsFilteredOut("my-bucket"))
	})

	t.Run("include list keeps matching bucket", func(t *testing.T) {
		filters := S3DiscoveryFilters{
			BucketNames: []string{"my-bucket", "other-bucket"},
		}
		require.False(t, filters.IsFilteredOut("my-bucket"))
	})

	t.Run("include list drops non-matching bucket", func(t *testing.T) {
		filters := S3DiscoveryFilters{
			BucketNames: []string{"my-bucket"},
		}
		require.True(t, filters.IsFilteredOut("other-bucket"))
	})

	t.Run("exclude list drops matching bucket", func(t *testing.T) {
		filters := S3DiscoveryFilters{
			ExcludeBucketNames: []string{"my-bucket"},
		}
		require.True(t, filters.IsFilteredOut("my-bucket"))
	})

	t.Run("exclude list keeps non-matching bucket", func(t *testing.T) {
		filters := S3DiscoveryFilters{
			ExcludeBucketNames: []string{"my-bucket"},
		}
		require.False(t, filters.IsFilteredOut("other-bucket"))
	})

	t.Run("exclude wins when bucket is in both include and exclude lists", func(t *testing.T) {
		filters := S3DiscoveryFilters{
			BucketNames:        []string{"my-bucket", "other-bucket"},
			ExcludeBucketNames: []string{"my-bucket"},
		}
		require.True(t, filters.IsFilteredOut("my-bucket"))
		require.False(t, filters.IsFilteredOut("other-bucket"))
	})
}

func TestDiscoveryFiltersFromOpts(t *testing.T) {
	t.Run("all opts are mapped to discovery filters correctly", func(t *testing.T) {
		opts := map[string]string{
			// DiscoveryFilters.Regions
			"regions": "us-east-1,us-west-1,eu-west-1",
			// DiscoveryFilters.ExcludeRegions
			"exclude:regions": "us-east-2,us-west-2,eu-west-2",
			// Ec2DiscoveryFilters.InstanceIds
			"ec2:instance-ids": "iid-1,iid-2",
			// Ec2DiscoveryFilters.ExcludeInstanceIds
			"ec2:exclude:instance-ids": "iid-1,iid-2",
			// GeneralDiscoveryFilters.Tags
			"tag:key1": "val1",
			"tag:key2": "val2",
			// GeneralDiscoveryFilters.ExcludeTags
			"exclude:tag:key1": "val1,val2",
			"exclude:tag:key2": "val3",
			// EcrDiscoveryFilters.Tags
			"ecr:tags": "tag1,tag2",
			// EcrDiscoveryFilters.ExcludeTags
			"ecr:exclude:tags": "tag1,tag2",
			// EcrDiscoveryFilters.PrivateRepositoryNames
			"ecr:private-repository-names": "priv1,priv2",
			// EcrDiscoveryFilters.PublicRepositoryNames
			"ecr:public-repository-names": "pub1,pub2",
			// EcrDiscoveryFilters.Scope
			"ecr:scope": "private",
			// S3DiscoveryFilters.BucketNames
			"s3:bucket-names": "bucket1,bucket2",
			// S3DiscoveryFilters.ExcludeBucketNames
			"s3:exclude:bucket-names": "bucket3,bucket4",
			// EcsDiscoveryFilters
			"ecs:only-running-containers": "true",
			"ecs:discover-images":         "T",
			"ecs:discover-instances":      "false",
			// Account-level filters
			"propagate-account-tags": "true",
			"account-tag:Owner":      "team-a",
			"account-tag:CostCenter": "cc-42",
		}
		expected := DiscoveryFilters{
			General: GeneralDiscoveryFilters{
				Regions:        []string{"us-east-1", "us-west-1", "eu-west-1"},
				ExcludeRegions: []string{"us-east-2", "us-west-2", "eu-west-2"},
				Tags: map[string]string{
					"key1": "val1",
					"key2": "val2",
				},
				ExcludeTags: map[string]string{
					"key1": "val1,val2",
					"key2": "val3",
				},
			},
			Ec2: Ec2DiscoveryFilters{
				InstanceIds:        []string{"iid-1", "iid-2"},
				ExcludeInstanceIds: []string{"iid-1", "iid-2"},
			},
			Ecs: EcsDiscoveryFilters{
				OnlyRunningContainers: true,
				DiscoverImages:        true,
				DiscoverInstances:     false,
			},
			Ecr: EcrDiscoveryFilters{
				Tags:                   []string{"tag1", "tag2"},
				ExcludeTags:            []string{"tag1", "tag2"},
				PrivateRepositoryNames: []string{"priv1", "priv2"},
				PublicRepositoryNames:  []string{"pub1", "pub2"},
				Scope:                  EcrScopePrivate,
			},
			S3: S3DiscoveryFilters{
				BucketNames:        []string{"bucket1", "bucket2"},
				ExcludeBucketNames: []string{"bucket3", "bucket4"},
			},
			PropagateAccountTags: true,
			AccountTags: map[string]string{
				"Owner":      "team-a",
				"CostCenter": "cc-42",
			},
		}

		actual := DiscoveryFiltersFromOpts(opts)
		require.Equal(t, expected, actual)
	})

	t.Run("empty opts are mapped to discovery filters correctly", func(t *testing.T) {
		expected := DiscoveryFilters{
			General: GeneralDiscoveryFilters{
				Regions:        []string{},
				ExcludeRegions: []string{},
				Tags:           map[string]string{},
				ExcludeTags:    map[string]string{},
			},
			Ec2: Ec2DiscoveryFilters{
				InstanceIds:        []string{},
				ExcludeInstanceIds: []string{},
			},
			Ecr: EcrDiscoveryFilters{
				Tags:                   []string{},
				ExcludeTags:            []string{},
				PrivateRepositoryNames: []string{},
				PublicRepositoryNames:  []string{},
			},
			S3: S3DiscoveryFilters{
				BucketNames:        []string{},
				ExcludeBucketNames: []string{},
			},
			Ecs:         EcsDiscoveryFilters{},
			AccountTags: map[string]string{},
		}
		actual := DiscoveryFiltersFromOpts(map[string]string{})
		require.Equal(t, expected, actual)
	})

	t.Run("nil opts are mapped to discovery filter correctly", func(t *testing.T) {
		expected := DiscoveryFilters{
			General: GeneralDiscoveryFilters{
				Regions:        []string{},
				ExcludeRegions: []string{},
				Tags:           map[string]string{},
				ExcludeTags:    map[string]string{},
			},
			Ec2: Ec2DiscoveryFilters{
				InstanceIds:        []string{},
				ExcludeInstanceIds: []string{},
			},
			Ecr: EcrDiscoveryFilters{
				Tags:                   []string{},
				ExcludeTags:            []string{},
				PrivateRepositoryNames: []string{},
				PublicRepositoryNames:  []string{},
			},
			S3: S3DiscoveryFilters{
				BucketNames:        []string{},
				ExcludeBucketNames: []string{},
			},
			Ecs:         EcsDiscoveryFilters{},
			AccountTags: map[string]string{},
		}
		actual := DiscoveryFiltersFromOpts(nil)
		require.Equal(t, expected, actual)
	})
}

func TestParseMapOpt(t *testing.T) {
	t.Run("parses map options correctly", func(t *testing.T) {
		opts := map[string]string{
			"tag:env":        "prod,staging",
			"tag:team":       "alpha",
			"exclude:tag:dc": "us-east,us-west",
		}
		result := parseMapOpt(opts, "tag:")
		expected := map[string]string{
			"env":  "prod,staging",
			"team": "alpha",
		}
		require.Equal(t, expected, result)
	})

	t.Run("returns empty map no matching keys", func(t *testing.T) {
		opts := map[string]string{
			"tag":            "some-value", // key is missing `:`
			"some-other-key": "some-value",
		}
		result := parseMapOpt(opts, "tag:")
		expected := map[string]string{}
		require.Equal(t, expected, result)
	})

	t.Run("returns empty map when there are no opts", func(t *testing.T) {
		opts := map[string]string{}
		result := parseMapOpt(opts, "tag:")
		expected := map[string]string{}
		require.Equal(t, expected, result)
	})
}

func TestBatchRepositoryNames(t *testing.T) {
	makeNames := func(n int) []string {
		names := make([]string, n)
		for i := range names {
			names[i] = "repo-" + strconv.Itoa(i)
		}
		return names
	}

	t.Run("no filter returns nil so the caller describes everything", func(t *testing.T) {
		require.Nil(t, batchRepositoryNames(nil))
		require.Nil(t, batchRepositoryNames([]string{}))
	})

	t.Run("within the limit returns a single batch", func(t *testing.T) {
		names := makeNames(3)
		batches := batchRepositoryNames(names)
		require.Len(t, batches, 1)
		require.Equal(t, names, batches[0])
	})

	t.Run("exactly at the limit stays a single batch", func(t *testing.T) {
		names := makeNames(ECRDescribeRepositoriesNameLimit)
		batches := batchRepositoryNames(names)
		require.Len(t, batches, 1)
		require.Len(t, batches[0], ECRDescribeRepositoriesNameLimit)
	})

	t.Run("over the limit splits into limit-sized batches", func(t *testing.T) {
		// 1000 names -> 10 batches of 100
		names := makeNames(1000)
		batches := batchRepositoryNames(names)
		require.Len(t, batches, 10)
		for _, b := range batches {
			require.Len(t, b, ECRDescribeRepositoriesNameLimit)
		}
		// every name is covered exactly once, in order
		var flat []string
		for _, b := range batches {
			flat = append(flat, b...)
		}
		require.Equal(t, names, flat)
	})

	t.Run("a partial trailing batch keeps the remainder", func(t *testing.T) {
		// 101 names -> 100 + 1
		names := makeNames(ECRDescribeRepositoriesNameLimit + 1)
		batches := batchRepositoryNames(names)
		require.Len(t, batches, 2)
		require.Len(t, batches[0], ECRDescribeRepositoriesNameLimit)
		require.Len(t, batches[1], 1)
	})

	t.Run("scope helpers batch the matching name list", func(t *testing.T) {
		f := EcrDiscoveryFilters{
			PrivateRepositoryNames: []string{"priv1", "priv2"},
			PublicRepositoryNames:  []string{"pub1"},
		}
		require.Equal(t, [][]string{{"priv1", "priv2"}}, f.PrivateRepositoryNameBatches())
		require.Equal(t, [][]string{{"pub1"}}, f.PublicRepositoryNameBatches())
	})
}
