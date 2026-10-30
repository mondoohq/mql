// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	batch_types "github.com/aws/aws-sdk-go-v2/service/batch/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A compute environment that is not ECS-backed reports no ECS settings at all.
// That is null, not DISABLED: Batch has not said Container Insights is off, it
// has said the setting does not apply. A DISABLED here would be a fabricated
// answer that a policy would read as a real one.
func TestBatchContainerInsightsAbsentIsNull(t *testing.T) {
	ce := &mqlAwsBatchComputeEnvironment{}

	got, err := ce.containerInsights()
	require.NoError(t, err)
	assert.Equal(t, "", got)
	assert.True(t, ce.ContainerInsights.IsNull())
	assert.True(t, ce.ContainerInsights.IsSet())
}

func TestBatchContainerInsightsModes(t *testing.T) {
	for _, mode := range []batch_types.ContainerInsights{
		batch_types.ContainerInsightsEnabled,
		batch_types.ContainerInsightsEnhanced,
		batch_types.ContainerInsightsDisabled,
	} {
		t.Run(string(mode), func(t *testing.T) {
			ce := &mqlAwsBatchComputeEnvironment{}
			ce.cacheEcsSettings = &batch_types.EcsSettings{ContainerInsights: mode}

			got, err := ce.containerInsights()
			require.NoError(t, err)
			assert.Equal(t, string(mode), got)
			assert.False(t, ce.ContainerInsights.IsNull())
		})
	}
}

func TestBatchCapacityTags(t *testing.T) {
	t.Run("no compute resources", func(t *testing.T) {
		ce := &mqlAwsBatchComputeEnvironment{}
		got, err := ce.capacityTags()
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("tags present", func(t *testing.T) {
		ce := &mqlAwsBatchComputeEnvironment{}
		ce.cacheComputeResources = &batch_types.ComputeResource{
			CapacityTags: map[string]string{"team": "platform"},
		}
		got, err := ce.capacityTags()
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"team": "platform"}, got)
	})
}
