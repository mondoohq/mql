// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestListSchedulerJobsPerLocation(t *testing.T) {
	// Measured: the Cloud Scheduler locations list for a project (2026-11-15)
	// begins with us-central1 and includes these regions.
	locations := []string{"us-central1", "asia-east1", "europe-west1"}

	t.Run("results keep location order", func(t *testing.T) {
		res, err := listSchedulerJobsPerLocation(context.Background(), locations, func(_ context.Context, location string) ([]string, error) {
			return []string{location + "/job"}, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"us-central1/job", "asia-east1/job", "europe-west1/job"}, res)
	})

	// Synthetic: a region the caller may not read; no target showed this.
	t.Run("a refused location is skipped", func(t *testing.T) {
		res, err := listSchedulerJobsPerLocation(context.Background(), locations, func(_ context.Context, location string) ([]string, error) {
			if location == "asia-east1" {
				return nil, status.Error(codes.PermissionDenied, "denied")
			}
			return []string{location}, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"us-central1", "europe-west1"}, res)
	})

	// Measured: ListJobs on locations/- answered InvalidArgument "Location '-'
	// is not a valid location"; an error like that must not read as no jobs.
	t.Run("any other error fails the listing", func(t *testing.T) {
		res, err := listSchedulerJobsPerLocation(context.Background(), locations, func(_ context.Context, location string) ([]string, error) {
			if location == "europe-west1" {
				return nil, status.Error(codes.InvalidArgument, "Location '-' is not a valid location.")
			}
			return []string{location}, nil
		})
		require.Error(t, err)
		assert.Nil(t, res)
	})
}
