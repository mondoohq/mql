// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsec2ebsconn

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"
)

func TestNewVolumeAttachmentLoc(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	loc1 := newVolumeAttachmentLoc()
	require.Equal(t, len(loc1), 8)
	require.Equal(t, strings.HasPrefix(loc1, "/dev/sd"), true)
}

func ebsMapping(device, volumeID string) types.InstanceBlockDeviceMapping {
	return types.InstanceBlockDeviceMapping{
		DeviceName: aws.String(device),
		Ebs:        &types.EbsInstanceBlockDevice{VolumeId: aws.String(volumeID)},
	}
}

func TestGetVolumeInfoForInstance(t *testing.T) {
	tests := []struct {
		name     string
		instance *types.Instance
		want     string // "" means no volume identified
	}{
		{
			name: "root device is matched exactly, not by substring",
			// The regression: /dev/xvda1 is a data volume, and "xvda" is a
			// substring of it, so the old code returned vol-data for an
			// instance whose root is /dev/xvda. That scans the wrong
			// filesystem and reports the wrong OS with no error.
			instance: &types.Instance{
				RootDeviceName: aws.String("/dev/xvda"),
				BlockDeviceMappings: []types.InstanceBlockDeviceMapping{
					ebsMapping("/dev/xvda1", "vol-data"),
					ebsMapping("/dev/xvda", "vol-root"),
				},
			},
			want: "vol-root",
		},
		{
			name: "root device outside the conventional names is found",
			instance: &types.Instance{
				RootDeviceName: aws.String("/dev/xvdb"),
				BlockDeviceMappings: []types.InstanceBlockDeviceMapping{
					ebsMapping("/dev/xvda", "vol-data"),
					ebsMapping("/dev/xvdb", "vol-root"),
				},
			},
			want: "vol-root",
		},
		{
			name: "sda1 root",
			instance: &types.Instance{
				RootDeviceName: aws.String("/dev/sda1"),
				BlockDeviceMappings: []types.InstanceBlockDeviceMapping{
					ebsMapping("/dev/sda1", "vol-root"),
					ebsMapping("/dev/sdf", "vol-data"),
				},
			},
			want: "vol-root",
		},
		{
			name: "single volume, no root device name",
			instance: &types.Instance{
				BlockDeviceMappings: []types.InstanceBlockDeviceMapping{
					ebsMapping("/dev/xvdz", "vol-only"),
				},
			},
			want: "vol-only",
		},
		{
			name: "no root device name falls back to a conventional name",
			instance: &types.Instance{
				BlockDeviceMappings: []types.InstanceBlockDeviceMapping{
					ebsMapping("/dev/sdf", "vol-data"),
					ebsMapping("/dev/xvda", "vol-root"),
				},
			},
			want: "vol-root",
		},
		{
			name: "no root device name and nothing conventional is not a guess",
			instance: &types.Instance{
				BlockDeviceMappings: []types.InstanceBlockDeviceMapping{
					ebsMapping("/dev/sdf", "vol-a"),
					ebsMapping("/dev/sdg", "vol-b"),
				},
			},
			want: "",
		},
		{
			name: "instance-store mapping carries no volume and is skipped",
			instance: &types.Instance{
				RootDeviceName: aws.String("/dev/xvda"),
				BlockDeviceMappings: []types.InstanceBlockDeviceMapping{
					{DeviceName: aws.String("/dev/xvdb")}, // Ebs is nil
					ebsMapping("/dev/xvda", "vol-root"),
				},
			},
			want: "vol-root",
		},
		{
			name: "only instance-store mappings",
			instance: &types.Instance{
				RootDeviceName: aws.String("/dev/xvda"),
				BlockDeviceMappings: []types.InstanceBlockDeviceMapping{
					{DeviceName: aws.String("/dev/xvda")},
				},
			},
			want: "",
		},
		{
			name:     "no mappings",
			instance: &types.Instance{RootDeviceName: aws.String("/dev/xvda")},
			want:     "",
		},
		{
			name:     "nil instance",
			instance: nil,
			want:     "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := GetVolumeInfoForInstance(test.instance)
			if test.want == "" {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, test.want, *got)
		})
	}
}
