// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsecs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
)

func TestParseECSContainerId(t *testing.T) {
	path := "//platformid.api.mondoo.app/runtime/aws/ecs/v1/accounts/185972265011/regions/us-east-1/container/vjtest/f088b38d61ac45d6a946b5aebbe7197a/314e35e0-2d0a-4408-b37e-16063461d73a"
	id, err := ParseMondooECSContainerId(path)
	require.NoError(t, err)
	assert.Equal(t, id.Account, "185972265011")
	assert.Equal(t, id.Region, "us-east-1")
	assert.Equal(t, id.Id, "vjtest/f088b38d61ac45d6a946b5aebbe7197a/314e35e0-2d0a-4408-b37e-16063461d73a")
}

func TestEC2RoleProviderInstanceIdentityUnix(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/container-identity.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	metadata := containerMetadata{conn, platform}
	ident, err := metadata.Identify()

	require.Nil(t, err)
	require.Equal(t, "fargate-app", ident.Name)
	require.Equal(t, "arn:aws:ecs:us-east-1:172746783610:container/vjtest/f088b38d61ac45d6a946b5aebbe7197a/314e35e0-2d0a-4408-b37e-16063461d73a", ident.ContainerArn)
	require.Equal(t, "f088b38d61ac45d6a946b5aebbe7197a-3681984407", ident.RuntimeID)
	require.Contains(t, ident.PlatformIds, "//platformid.api.mondoo.app/runtime/docker/containers/f088b38d61ac45d6a946b5aebbe7197a-3681984407")
	require.Contains(t, ident.PlatformIds, "//platformid.api.mondoo.app/runtime/aws/ecs/v1/accounts/172746783610/regions/us-east-1/container/vjtest/f088b38d61ac45d6a946b5aebbe7197a/314e35e0-2d0a-4408-b37e-16063461d73a")
	require.Contains(t, ident.AccountPlatformID, "//platformid.api.mondoo.app/runtime/aws/accounts/172746783610")
}
