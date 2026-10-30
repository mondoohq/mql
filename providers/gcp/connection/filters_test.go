// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStorageIsFilteredOut(t *testing.T) {
	t.Run("no filters keeps every bucket", func(t *testing.T) {
		filters := StorageDiscoveryFilters{}
		require.False(t, filters.IsFilteredOut("my-bucket"))
	})

	t.Run("include list keeps matching bucket", func(t *testing.T) {
		filters := StorageDiscoveryFilters{
			BucketNames: []string{"my-bucket", "other-bucket"},
		}
		require.False(t, filters.IsFilteredOut("my-bucket"))
	})

	t.Run("include list drops non-matching bucket", func(t *testing.T) {
		filters := StorageDiscoveryFilters{
			BucketNames: []string{"my-bucket"},
		}
		require.True(t, filters.IsFilteredOut("other-bucket"))
	})

	t.Run("exclude list drops matching bucket", func(t *testing.T) {
		filters := StorageDiscoveryFilters{
			ExcludeBucketNames: []string{"my-bucket"},
		}
		require.True(t, filters.IsFilteredOut("my-bucket"))
	})

	t.Run("exclude list keeps non-matching bucket", func(t *testing.T) {
		filters := StorageDiscoveryFilters{
			ExcludeBucketNames: []string{"my-bucket"},
		}
		require.False(t, filters.IsFilteredOut("other-bucket"))
	})

	t.Run("exclude wins when bucket is in both include and exclude lists", func(t *testing.T) {
		filters := StorageDiscoveryFilters{
			BucketNames:        []string{"my-bucket", "other-bucket"},
			ExcludeBucketNames: []string{"my-bucket"},
		}
		require.True(t, filters.IsFilteredOut("my-bucket"))
		require.False(t, filters.IsFilteredOut("other-bucket"))
	})
}

func TestDiscoveryFiltersFromOpts(t *testing.T) {
	t.Run("opts are mapped to discovery filters correctly", func(t *testing.T) {
		opts := map[string]string{
			"storage:bucket-names":         "bucket1,bucket2",
			"storage:exclude:bucket-names": "bucket3,bucket4",
		}
		expected := DiscoveryFilters{
			Storage: StorageDiscoveryFilters{
				BucketNames:        []string{"bucket1", "bucket2"},
				ExcludeBucketNames: []string{"bucket3", "bucket4"},
			},
		}
		require.Equal(t, expected, DiscoveryFiltersFromOpts(opts))
	})

	t.Run("empty opts are mapped to discovery filters correctly", func(t *testing.T) {
		expected := DiscoveryFilters{
			Storage: StorageDiscoveryFilters{
				BucketNames:        []string{},
				ExcludeBucketNames: []string{},
			},
		}
		require.Equal(t, expected, DiscoveryFiltersFromOpts(map[string]string{}))
	})

	t.Run("nil opts are mapped to discovery filters correctly", func(t *testing.T) {
		expected := DiscoveryFilters{
			Storage: StorageDiscoveryFilters{
				BucketNames:        []string{},
				ExcludeBucketNames: []string{},
			},
		}
		require.Equal(t, expected, DiscoveryFiltersFromOpts(nil))
	})

	t.Run("propagate-project-labels defaults to false", func(t *testing.T) {
		require.False(t, DiscoveryFiltersFromOpts(map[string]string{}).PropagateProjectLabels)
	})

	t.Run("propagate-project-labels is parsed when enabled", func(t *testing.T) {
		opts := map[string]string{"propagate-project-labels": "true"}
		require.True(t, DiscoveryFiltersFromOpts(opts).PropagateProjectLabels)
	})
}
