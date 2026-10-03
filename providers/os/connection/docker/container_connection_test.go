// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

// The two TestAssetNameForRemoteImages* tests below use a tag reference
// (mirror.gcr.io/library/busybox:1.36.1) rather than a digest reference, on
// purpose: the goal is to exercise the tag→digest resolution path in
// NewContainerImageConnection. The expected digest is hardcoded in the
// assertions so a helper regression (wrong short-hash length, stray "sha256:"
// prefix, etc.) would still be caught. If mirror.gcr.io ever rebuilds the
// tag, update the hardcoded digest to match — this is preferable to a
// dynamic lookup, which would make the assertions tautological against the
// production helpers.
// mirror.gcr.io is Google's anonymous pull-through cache for Docker Hub and
// is not bound to docker-credential-gcloud, which made the previous gcr.io
// fixture flake on CI.

// To test this specific case, we cannot use a stored image, we need to call remote.Get
func TestAssetNameForRemoteImages(t *testing.T) {
	var err error
	var conn *tar.Connection
	var asset *inventory.Asset
	retries := 3
	counter := 0

	config := &inventory.Config{
		Type: "docker-image",
		Host: "mirror.gcr.io/library/busybox:1.36.1",
	}
	asset = &inventory.Asset{
		Connections: []*inventory.Config{config},
	}

	for {
		conn, err = NewContainerImageConnection(0, config, asset)
		if counter > retries || (err == nil && conn != nil) {
			break
		}
		counter++
	}
	require.NoError(t, err)
	require.NotNil(t, conn)

	assert.True(t, config.DelayDiscovery)
	assert.Equal(t, "mirror.gcr.io/library/busybox@73aaf090f3d8", asset.Name)
	assert.Contains(t, asset.PlatformIds, "//platformid.api.mondoo.app/runtime/docker/images/73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662")
}

// To test this specific case, we cannot use a stored image, we need to call remote.Get
func TestAssetNameForRemoteImages_DisableDelayedDiscovery(t *testing.T) {
	var err error
	var conn *tar.Connection
	var asset *inventory.Asset
	retries := 3
	counter := 0

	config := &inventory.Config{
		Type: "docker-image",
		Host: "mirror.gcr.io/library/busybox:1.36.1",
		Options: map[string]string{
			plugin.DISABLE_DELAYED_DISCOVERY_OPTION: "true",
		},
	}
	asset = &inventory.Asset{
		Connections: []*inventory.Config{config},
	}

	for {
		conn, err = NewContainerImageConnection(0, config, asset)
		if counter > retries || (err == nil && conn != nil) {
			break
		}
		counter++
	}
	require.NoError(t, err)
	require.NotNil(t, conn)

	assert.False(t, config.DelayDiscovery)
	assert.Equal(t, "mirror.gcr.io/library/busybox@73aaf090f3d8", asset.Name)
	assert.Contains(t, asset.PlatformIds, "//platformid.api.mondoo.app/runtime/docker/images/73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662")
}

func fetchAndCreateImage(t *testing.T, ctx context.Context, dClient *client.Client, img string) client.ContainerCreateResult {
	// If docker is not available, then skip the test.
	_, err := dClient.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		t.SkipNow()
	}

	responseBody, err := dClient.ImagePull(ctx, img, client.ImagePullOptions{})
	defer func() {
		err = responseBody.Close()
		if err != nil {
			panic(err)
		}
	}()
	require.NoError(t, err)

	_, err = io.Copy(os.Stdout, responseBody)
	require.NoError(t, err)

	// Make sure the docker image is cleaned up
	defer func() {
		_, err := dClient.ImageRemove(ctx, img, client.ImageRemoveOptions{Force: true})
		// ignore error, worst case is that the image is not removed but parallel tests may fail otherwise
		fmt.Printf("failed to cleanup pre-pulled docker image: %v", err)
	}()

	cfg := &container.Config{
		AttachStdin:  false,
		AttachStdout: false,
		AttachStderr: false,
		StdinOnce:    false,
		Image:        img,
	}

	uuidVal := uuid.New()
	created, err := dClient.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:           cfg,
		HostConfig:       &container.HostConfig{},
		NetworkingConfig: &network.NetworkingConfig{},
		Platform:         &specs.Platform{},
		Name:             uuidVal.String(),
	})
	require.NoError(t, err)

	_, err = dClient.ContainerStart(ctx, created.ID, client.ContainerStartOptions{})
	require.NoError(t, err)

	return created
}

// TestDockerContainerConnection creates a new running container and tests the connection
func TestDockerContainerConnection(t *testing.T) {
	ctx := context.Background()
	image := "docker.io/nginx:stable"
	dClient, err := GetDockerClient()
	assert.NoError(t, err)
	created := fetchAndCreateImage(t, ctx, dClient, image)

	// Make sure the container is cleaned up
	defer func() {
		_, err := dClient.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{Force: true})
		require.NoError(t, err)
	}()

	fmt.Println("inject: " + created.ID)
	conn, err := NewContainerConnection(0, &inventory.Config{
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

	cmd, err := conn.RunCommand("ls /")
	require.NoError(t, err)
	assert.NotNil(t, cmd)
	assert.Equal(t, 0, cmd.ExitStatus)
}

// An amd64 image running under emulation on an arm64 Docker Desktop reported
// the daemon's arm64, so its packages got arm64 purls and matched the wrong
// advisories. The image's architecture wins.
func TestContainerArchitecture(t *testing.T) {
	assert.Equal(t, "amd64", containerArchitecture("amd64", "", "arm64"),
		"a multi-platform image inspects with no architecture; the manifest names it")
	assert.Equal(t, "amd64", containerArchitecture("", "amd64", "arm64"))
	assert.Equal(t, "arm64", containerArchitecture("", "", "arm64"), "the daemon's is the fallback")
	assert.Equal(t, "", containerArchitecture("", "", ""))
}
