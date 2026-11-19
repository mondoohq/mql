// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"testing"

	"cloud.google.com/go/cloudbuild/apiv1/v2/cloudbuildpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestBuildTriggerGithubConfig(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result, err := buildTriggerGithubConfig(nil, "parent", nil)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestBuildTriggerPubsubConfig(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result, err := buildTriggerPubsubConfig(nil, "parent", "", nil)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestBuildTriggerWebhookConfig(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result, err := buildTriggerWebhookConfig(nil, "parent", nil)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestBuildTriggerRepoEventConfig(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result, err := buildTriggerRepoEventConfig(nil, "parent", nil)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestBuildWorkerPoolWorkerConfig(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result, err := buildWorkerPoolWorkerConfig(nil, "parent", nil)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("nil worker config within private pool returns nil", func(t *testing.T) {
		cfg := &cloudbuildpb.PrivatePoolV1Config{
			WorkerConfig: nil,
		}
		result, err := buildWorkerPoolWorkerConfig(nil, "parent", cfg)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestBuildWorkerPoolNetworkConfig(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result, err := buildWorkerPoolNetworkConfig(nil, "parent", nil)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("nil network config within private pool returns nil", func(t *testing.T) {
		cfg := &cloudbuildpb.PrivatePoolV1Config{
			NetworkConfig: nil,
		}
		result, err := buildWorkerPoolNetworkConfig(nil, "parent", cfg)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestListCloudBuildPerLocation(t *testing.T) {
	// Measured: Cloud Build v2 locations list for a project (2026-11-15) starts
	// with these entries; ListWorkerPools answers 400 INVALID_ARGUMENT for
	// "global" and 200 for every region.
	locations := []string{"africa-south1", "global", "us-central1"}

	t.Run("results keep location order", func(t *testing.T) {
		res, err := listCloudBuildPerLocation(context.Background(), locations, func(_ context.Context, location string) ([]string, error) {
			return []string{location + "/a", location + "/b"}, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []string{
			"africa-south1/a", "africa-south1/b",
			"global/a", "global/b",
			"us-central1/a", "us-central1/b",
		}, res)
	})

	t.Run("a location that does not offer the resource is skipped", func(t *testing.T) {
		res, err := listCloudBuildPerLocation(context.Background(), locations, func(_ context.Context, location string) ([]string, error) {
			if location == "global" {
				return nil, status.Error(codes.InvalidArgument, "Request contains an invalid argument.")
			}
			return []string{location}, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"africa-south1", "us-central1"}, res)
	})

	// Synthetic: a transient failure in one region; no target showed this.
	t.Run("any other error fails the listing instead of dropping the location", func(t *testing.T) {
		res, err := listCloudBuildPerLocation(context.Background(), locations, func(_ context.Context, location string) ([]string, error) {
			if location == "us-central1" {
				return nil, status.Error(codes.Unavailable, "unavailable")
			}
			return []string{location}, nil
		})
		require.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("no locations lists nothing", func(t *testing.T) {
		res, err := listCloudBuildPerLocation(context.Background(), nil, func(_ context.Context, location string) ([]string, error) {
			return []string{location}, nil
		})
		require.NoError(t, err)
		assert.Empty(t, res)
	})
}
