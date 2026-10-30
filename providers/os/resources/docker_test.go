// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type typedConnection struct {
	shared.Connection
	connType shared.ConnectionType
}

func (c *typedConnection) Type() shared.ConnectionType { return c.connType }

// The docker client is built from the provider process's environment, so it
// reaches the daemon on the machine running mql. For a remote transport that
// daemon belongs to the scanner, not the asset.
func TestCheckDockerDaemonIsTheAssets(t *testing.T) {
	allowed := []shared.ConnectionType{
		shared.Type_Local,
		shared.Type_DockerContainer,
		shared.Type_DockerImage,
		shared.Type_DockerSnapshot,
		shared.Type_DockerFile,
		shared.Type_DockerRegistry,
		shared.Type_ContainerRegistry,
		shared.Type_RegistryImage,
		"mock",
	}
	for _, ct := range allowed {
		t.Run("allows "+ct.String(), func(t *testing.T) {
			runtime := &plugin.Runtime{Connection: &typedConnection{connType: ct}}
			require.NoError(t, checkDockerDaemonIsTheAssets(runtime))
		})
	}

	refused := []shared.ConnectionType{
		shared.Type_SSH,
		shared.Type_Winrm,
		shared.Type_Vagrant,
		shared.Type_FileSystem,
		shared.Type_Tar,
		shared.Type_Device,
	}
	for _, ct := range refused {
		t.Run("refuses "+ct.String(), func(t *testing.T) {
			runtime := &plugin.Runtime{Connection: &typedConnection{connType: ct}}
			err := checkDockerDaemonIsTheAssets(runtime)
			require.Error(t, err, "%s must not be served by the scanner's daemon", ct)
			assert.Contains(t, err.Error(), ct.String())
		})
	}
}

type fakeContainerLister struct {
	running []container.Summary
	stopped []container.Summary
}

// ContainerList mimics the daemon: without All it answers only the running
// (and paused) containers, like `docker ps`.
func (f *fakeContainerLister) ContainerList(_ context.Context, opts client.ContainerListOptions) (client.ContainerListResult, error) {
	items := append([]container.Summary{}, f.running...)
	if opts.All {
		items = append(items, f.stopped...)
	}
	return client.ContainerListResult{Items: items}, nil
}

func TestListAllDockerContainersIncludesStopped(t *testing.T) {
	lister := &fakeContainerLister{
		running: []container.Summary{{ID: "web", State: container.StateRunning}},
		stopped: []container.Summary{
			{ID: "exited", State: container.StateExited},
			{ID: "created", State: container.StateCreated},
		},
	}
	got, err := listAllDockerContainers(context.Background(), lister)
	require.NoError(t, err)
	ids := []string{}
	for _, c := range got {
		ids = append(ids, c.ID)
	}
	assert.ElementsMatch(t, []string{"web", "exited", "created"}, ids)
}

type failingContainerLister struct{}

func (failingContainerLister) ContainerList(context.Context, client.ContainerListOptions) (client.ContainerListResult, error) {
	return client.ContainerListResult{}, errors.New("permission denied while trying to connect to the Docker daemon socket")
}

func TestListAllDockerContainersPropagatesError(t *testing.T) {
	_, err := listAllDockerContainers(context.Background(), failingContainerLister{})
	require.Error(t, err)
}

// A dangling image on docker.io 1.13 / 18.09 (Ubuntu 16.04, 18.04), as
// GET /images/json returned it.
func TestDockerImageRefsDropsNonePlaceholders(t *testing.T) {
	assert.Empty(t, dockerImageRefs([]string{"<none>:<none>"}, dockerNoneTag))
	assert.Empty(t, dockerImageRefs([]string{"<none>@<none>"}, dockerNoneDigest))
	assert.Empty(t, dockerImageRefs(nil, dockerNoneTag))
	assert.Equal(t,
		[]any{"alpine:3.20", "alpine:latest"},
		dockerImageRefs([]string{"alpine:3.20", "alpine:latest"}, dockerNoneTag))
	assert.Equal(t,
		[]any{"alpine@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5"},
		dockerImageRefs([]string{"alpine@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5"}, dockerNoneDigest))
}
