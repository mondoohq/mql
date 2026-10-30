// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/stretchr/testify/require"
)

func TestValidateAndParseARN(t *testing.T) {
	tests := []struct {
		name            string
		arn             string
		expectedService string
		wantErr         bool
	}{
		{
			name:            "valid ecs arn",
			arn:             "arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster",
			expectedService: "ecs",
			wantErr:         false,
		},
		{
			name:            "sts arn instead of ecs arn",
			arn:             "arn:aws:sts::162854405951", // bug #6370
			expectedService: "ecs",
			wantErr:         true,
		},
		{
			name:            "invalid arn format - too short",
			arn:             "arn:aws:ecs",
			expectedService: "ecs",
			wantErr:         true,
		},
		{
			name:            "not an arn",
			arn:             "my-cluster",
			expectedService: "ecs",
			wantErr:         true,
		},
		{
			name:            "wrong service",
			arn:             "arn:aws:s3:::my-bucket",
			expectedService: "ecs",
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateAndParseARN(tt.arn, tt.expectedService)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, tt.expectedService, got.Service)
			}
		})
	}
}

// The account used for verification had no GPU container instances or GPU
// task definitions, so these cases are synthetic, shaped after the ECS API
// reference for sharingStrategy and gpuDevices.

func TestEcsGpuSharingArgs(t *testing.T) {
	// Synthetic: a container with exclusive GPUs (or none) has no strategy.
	args := ecsGpuSharingArgs(nil)
	require.Len(t, args, 3)
	for name, v := range args {
		require.Nil(t, v.Value, name)
	}

	// Synthetic: NVIDIA MPS with a memory allocation and a compute cap.
	args = ecsGpuSharingArgs(&ecstypes.SharingStrategyMemberNvidiaMps{Value: ecstypes.NvidiaMpsAllocation{
		Memory:            aws.Int32(4096),
		MaxComputePercent: aws.Int32(50),
	}})
	require.Equal(t, "NVIDIA_MPS", args["gpuSharingStrategy"].Value)
	require.Equal(t, int64(4096), args["gpuSharingMemoryInMiB"].Value)
	require.Equal(t, int64(50), args["gpuSharingMaxComputePercent"].Value)

	// Synthetic: no compute cap set reads null, not 0 percent.
	args = ecsGpuSharingArgs(&ecstypes.SharingStrategyMemberNvidiaMps{Value: ecstypes.NvidiaMpsAllocation{
		Memory: aws.Int32(2048),
	}})
	require.Equal(t, int64(2048), args["gpuSharingMemoryInMiB"].Value)
	require.Nil(t, args["gpuSharingMaxComputePercent"].Value)
}

func TestEcsGpuRequirementSharing(t *testing.T) {
	mps := &ecstypes.SharingStrategyMemberNvidiaMps{Value: ecstypes.NvidiaMpsAllocation{Memory: aws.Int32(1024)}}
	// Synthetic: the sharing strategy sits on the GPU requirement, next to others.
	got := ecsGpuRequirementSharing([]ecstypes.ResourceRequirement{
		{Type: ecstypes.ResourceTypeInferenceAccelerator, Value: aws.String("device_1")},
		{Type: ecstypes.ResourceTypeGpu, SharingStrategy: mps},
	})
	require.Same(t, mps, got)

	// Synthetic: a GPU count without a strategy means exclusive GPUs.
	require.Nil(t, ecsGpuRequirementSharing([]ecstypes.ResourceRequirement{
		{Type: ecstypes.ResourceTypeGpu, Value: aws.String("1")},
	}))
	require.Nil(t, ecsGpuRequirementSharing(nil))
}

func TestEcsGpuDevices(t *testing.T) {
	// Synthetic: one GPU shared by two MPS containers and one idle GPU whose
	// memory counters were not reported.
	got := ecsGpuDevices([]ecstypes.GpuDevice{
		{
			GpuId:                aws.String("GPU-aaaa"),
			SharingMode:          ecstypes.GpuSharingModeNvidiaMps,
			ContainerCount:       aws.Int32(2),
			TotalMemoryInMiB:     aws.Int32(23028),
			RemainingMemoryInMiB: aws.Int32(15028),
		},
		{GpuId: aws.String("GPU-bbbb"), SharingMode: ecstypes.GpuSharingModeIdle},
	})
	require.Equal(t, []any{
		map[string]any{
			"gpuId":                "GPU-aaaa",
			"sharingMode":          "NVIDIA_MPS",
			"containerCount":       int64(2),
			"totalMemoryInMiB":     int64(23028),
			"remainingMemoryInMiB": int64(15028),
		},
		map[string]any{
			"gpuId":                "GPU-bbbb",
			"sharingMode":          "IDLE",
			"containerCount":       nil,
			"totalMemoryInMiB":     nil,
			"remainingMemoryInMiB": nil,
		},
	}, got)

	// Synthetic: an instance without GPU sharing support reports an empty list.
	require.Equal(t, []any{}, ecsGpuDevices(nil))
}
