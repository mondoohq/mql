// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"context"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"testing"
)

func TestSnapshotConnection(t *testing.T) {
	ctx := context.Background()
	image := "docker.io/nginx:stable"
	dClient, err := GetDockerClient()
	assert.NoError(t, err)
	created := fetchAndCreateImage(t, ctx, dClient, image)
	// Make sure the container is cleaned up
	defer func() {
		_, err := dClient.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{
			Force: true,
		})
		require.NoError(t, err)
	}()

	conn, err := NewSnapshotConnection(0, &inventory.Config{
		Host: created.ID,
	}, &inventory.Asset{
		// for the test we need to set the platform
		Platform: &inventory.Platform{
			Name:    "debian",
			Version: "11",
			Family:  []string{"debian", "linux"},
		},
	})
	require.NoError(t, err)

	fi, err := conn.FileInfo("/etc/os-release")
	require.NoError(t, err)
	assert.NotNil(t, fi)
	assert.True(t, fi.Size > 0)
}
