// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

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
	"go.mondoo.com/mql/providers/os/connection/docker"
)

func TestDockerProcsList(t *testing.T) {
	img := "docker.io/nginx:stable"
	ctx := context.Background()
	dClient, err := docker.GetDockerClient()
	assert.NoError(t, err)

	// If docker is not available, then skip the test.
	_, err = dClient.ServerVersion(ctx, client.ServerVersionOptions{})
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

	// Make sure the container is cleaned up
	defer func() {
		_, err := dClient.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{Force: true})
		require.NoError(t, err)
	}()

	fmt.Println("inject: " + created.ID)
	conn, err := docker.NewContainerConnection(0, &inventory.Config{
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

	pMan, err := ResolveManager(conn)
	assert.NoError(t, err)

	proc, err := pMan.Process(1)
	assert.NoError(t, err)
	assert.NotEmpty(t, proc)
}
