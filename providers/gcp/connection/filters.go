// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"slices"

	"go.mondoo.com/mql/providers-sdk/v1/util/filteropts"
)

// DiscoveryFilters holds the per-service filters used to narrow discovery.
type DiscoveryFilters struct {
	Storage StorageDiscoveryFilters
	// PropagateProjectLabels, when enabled, merges each project's labels into
	// every asset discovered under that project (an asset's own labels win on
	// collision). GCP resource labels do not inherit from the parent project on
	// their own, so this mirrors the AWS "propagate-account-tags" behavior.
	// Note: Resource Manager tags already inherit from project/folder/org
	// natively and are unaffected by this option.
	PropagateProjectLabels bool
}

// DiscoveryFiltersFromOpts builds the discovery filters from the raw --filters
// key/value options passed on the connection config.
func DiscoveryFiltersFromOpts(opts map[string]string) DiscoveryFilters {
	return DiscoveryFilters{
		Storage: StorageDiscoveryFilters{
			BucketNames:        filteropts.ParseCsvSliceOpt(opts, "storage:bucket-names"),
			ExcludeBucketNames: filteropts.ParseCsvSliceOpt(opts, "storage:exclude:bucket-names"),
		},
		PropagateProjectLabels: filteropts.ParseBoolOpt(opts, "propagate-project-labels", false),
	}
}

type StorageDiscoveryFilters struct {
	BucketNames        []string
	ExcludeBucketNames []string
}

// note: if this function returns `true`, it means that the bucket should be skipped
func (f StorageDiscoveryFilters) IsFilteredOut(bucketName string) bool {
	if len(f.BucketNames) > 0 && !slices.Contains(f.BucketNames, bucketName) {
		return true
	}
	return slices.Contains(f.ExcludeBucketNames, bucketName)
}
