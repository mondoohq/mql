// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build debugtest
// +build debugtest

package docker

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startContainer() (*client.Client, string, error) {
	// os.Setenv("DOCKER_API_VERSION", "1.26")
	// Start new docker container
	ctx := context.Background()
	var err error
	// Honor DOCKER_HOST and the active docker context, same as production code paths.
	dockerClient, err := GetDockerClient()
	if err != nil {
		return nil, "", err
	}

	// ensure we kill container if something went wrong during assertion
	// we can ignore errors here
	dockerClient.ContainerKill(ctx, "motor-docker-test", client.ContainerKillOptions{Signal: "SIGKILL"})
	dockerClient.ContainerRemove(ctx, "motor-docker-test", client.ContainerRemoveOptions{Force: true})

	imageName := "ubuntu"

	out, err := dockerClient.ImagePull(ctx, imageName, client.ImagePullOptions{})
	if err != nil {
		return nil, "", err
	}
	io.Copy(os.Stdout, out)

	resp, err := dockerClient.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image: imageName,
			Cmd:   []string{"/bin/bash"},
			Tty:   true,
		},
		Name: "motor-docker-test",
	})
	if err != nil {
		return nil, "", err
	}

	if _, err := dockerClient.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		return nil, "", err
	}
	return dockerClient, resp.ID, nil
}

func tearDownContainer(dockerClient *client.Client, containerID string) error {
	// Stop Container
	_, err := dockerClient.ContainerKill(context.Background(), containerID, client.ContainerKillOptions{Signal: "SIGKILL"})
	return err
}

func TestDockerCommand(t *testing.T) {
	dockerClient, containerID, err := startContainer()
	require.NoError(t, err)
	defer tearDownContainer(dockerClient, containerID)

	// Execute tests
	t.Run("echo", func(t *testing.T) {
		c := &Command{Client: dockerClient, Container: containerID}
		cmd, err := c.Exec("echo 'test'")
		require.NoError(t, err)
		assert.Equal(t, "echo 'test'", cmd.Command, "they should be equal")

		stdout, _ := io.ReadAll(cmd.Stdout)
		assert.Equal(t, "test\n", string(stdout), "output should be correct")
		stderr, _ := io.ReadAll(cmd.Stderr)
		assert.Equal(t, "", string(stderr), "output should be correct")
	})

	t.Run("echo pipe", func(t *testing.T) {
		cErr := &Command{Client: dockerClient, Container: containerID}

		cmd, err := cErr.Exec("echo 'This message goes to stderr' >&2")
		require.NoError(t, err)

		assert.Equal(t, "echo 'This message goes to stderr' >&2", cmd.Command, "they should be equal")

		stdout, _ := io.ReadAll(cmd.Stdout)
		assert.Equal(t, "", string(stdout), "output should be correct")

		stderr, _ := io.ReadAll(cmd.Stderr)
		assert.Equal(t, "This message goes to stderr\n", string(stderr), "output should be correct")
	})
}
