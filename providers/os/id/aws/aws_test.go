// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aws

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
)

func TestDetectInstance(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/instance.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	identifier, name, related := Detect(conn, platform)

	assert.Equal(t, "//platformid.api.mondoo.app/runtime/aws/ec2/v1/accounts/123456789012/regions/us-west-2/instances/i-1234567890abcdef0", identifier)
	assert.Equal(t, "ec2-name", name)
	require.Len(t, related, 1)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/aws/accounts/123456789012", related[0])
}

func TestDetectInstanceArm(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/instancearm.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	identifier, name, related := Detect(conn, platform)

	assert.Equal(t, "//platformid.api.mondoo.app/runtime/aws/ec2/v1/accounts/123456789012/regions/us-west-2/instances/i-1234567890abcdef0", identifier)
	assert.Equal(t, "ec2-name", name)
	require.Len(t, related, 1)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/aws/accounts/123456789012", related[0])
}

func TestDetectNotInstance(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/notinstance.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	identifier, name, related := Detect(conn, platform)

	assert.Equal(t, "", identifier)
	assert.Equal(t, "", name)

	require.Len(t, related, 0)
}

func TestDetectContainer(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/container.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	identifier, name, related := Detect(conn, platform)

	assert.Equal(t, "//platformid.api.mondoo.app/runtime/aws/ecs/v1/accounts/172746783610/regions/us-east-1/container/vjtest/f088b38d61ac45d6a946b5aebbe7197a/314e35e0-2d0a-4408-b37e-16063461d73a", identifier)
	assert.Equal(t, "fargate-app", name)
	require.Len(t, related, 1)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/aws/accounts/172746783610", related[0])
}

func TestIsBottlerocketOnAWS(t *testing.T) {
	tests := []struct {
		name     string
		platform *inventory.Platform
		want     bool
	}{
		{
			// The variant EKS nodes run, and the case this exists for: no
			// cloud-init on disk, so nothing else marks the host as AWS.
			name: "bottlerocket aws-k8s variant via labels",
			platform: &inventory.Platform{
				Name:   "bottlerocket",
				Labels: map[string]string{"variant-id": "aws-k8s-1.34"},
			},
			want: true,
		},
		{
			name: "bottlerocket aws-ecs variant via metadata",
			platform: &inventory.Platform{
				Name:     "bottlerocket",
				Metadata: map[string]string{"variant-id": "aws-ecs-2-fips"},
			},
			want: true,
		},
		{
			name: "bottlerocket vmware variant is not aws",
			platform: &inventory.Platform{
				Name:   "bottlerocket",
				Labels: map[string]string{"variant-id": "vmware-k8s-1.34"},
			},
			want: false,
		},
		{
			name: "bottlerocket metal variant is not aws",
			platform: &inventory.Platform{
				Name:   "bottlerocket",
				Labels: map[string]string{"variant-id": "metal-k8s-1.34"},
			},
			want: false,
		},
		{
			name:     "bottlerocket without a variant",
			platform: &inventory.Platform{Name: "bottlerocket"},
			want:     false,
		},
		{
			// The aws- prefix only carries platform meaning under
			// Bottlerocket's variant naming, so it must not be trusted
			// anywhere else.
			name: "non-bottlerocket platform with an aws- variant",
			platform: &inventory.Platform{
				Name:   "amazonlinux",
				Labels: map[string]string{"variant-id": "aws-something"},
			},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, isBottlerocketOnAWS(test.platform))
		})
	}
}
