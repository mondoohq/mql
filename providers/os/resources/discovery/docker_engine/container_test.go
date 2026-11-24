// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker_engine

import (
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestDockerContainerImageName(t *testing.T) {
	// Inspect of a container started from alpine/socat:1.8.0.3.
	c := container.InspectResponse{
		Image:  "sha256:beb4a68d9e4fe6b0f21ea774a0fde6c31f580dde6368939ed70100c5385b015e",
		Config: &container.Config{Image: "alpine/socat:1.8.0.3"},
	}
	assert.Equal(t, "alpine/socat:1.8.0.3", dockerContainerImageName(c))

	c.Config = nil
	assert.Equal(t, "sha256:beb4a68d9e4fe6b0f21ea774a0fde6c31f580dde6368939ed70100c5385b015e", dockerContainerImageName(c))
}

func TestIsLocalDaemon(t *testing.T) {
	assert.True(t, isLocalDaemon("unix:///var/run/docker.sock"))
	assert.True(t, isLocalDaemon("unix:///run/user/1000/podman/podman.sock"))
	assert.True(t, isLocalDaemon("npipe:////./pipe/docker_engine"))
	assert.False(t, isLocalDaemon("tcp://10.0.0.5:2376"))
	assert.False(t, isLocalDaemon("ssh://admin@nas"))
	assert.False(t, isLocalDaemon(""))
}

func TestLocalHostRef(t *testing.T) {
	host := &inventory.Asset{
		Id:   "host-1",
		Name: "nas",
		PlatformIds: []string{
			"//platformid.api.mondoo.app/hostname/nas.lan",
			"//platformid.api.mondoo.app/machineid/0f3c9a1e8b7d4e6f9a2b1c3d4e5f6a7b",
		},
	}
	discovery := func(t *testing.T, daemonHost string) *dockerEngineDiscovery {
		c, err := client.New(client.WithHost(daemonHost))
		require.NoError(t, err)
		return &dockerEngineDiscovery{Client: c}
	}

	t.Run("local socket names the host by all its platform ids", func(t *testing.T) {
		ref := discovery(t, "unix:///var/run/docker.sock").localHostRef(host)
		require.NotNil(t, ref)
		assert.Equal(t, "host-1", ref.Id)
		assert.Equal(t, host.PlatformIds, ref.PlatformIds)
		// Identity only: nothing else of the host is copied.
		assert.Empty(t, ref.Name)
	})
	t.Run("remote daemon is not the scanned host", func(t *testing.T) {
		assert.Nil(t, discovery(t, "tcp://10.0.0.5:2376").localHostRef(host))
	})
	t.Run("no host", func(t *testing.T) {
		assert.Nil(t, discovery(t, "unix:///var/run/docker.sock").localHostRef(nil))
	})
	t.Run("host without platform ids", func(t *testing.T) {
		assert.Nil(t, discovery(t, "unix:///var/run/docker.sock").localHostRef(&inventory.Asset{Id: "host-1"}))
	})
}

func TestContainerHostRelationships(t *testing.T) {
	const id = "4f1c2e9a7b3d5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f"
	hostRef := &inventory.Asset{PlatformIds: []string{"//platformid.api.mondoo.app/machineid/0f3c9a1e"}}

	rels := containerHostRelationships(hostRef, id)
	require.Len(t, rels, 1)
	assert.Same(t, hostRef, rels[0].Asset)
	// The anchor is the host's docker.container resource for this container,
	// whose ID is the container's full ID.
	assert.Equal(t, "docker.container", rels[0].ResourceType)
	assert.Equal(t, id, rels[0].ResourceId)

	assert.Nil(t, containerHostRelationships(nil, id))
	assert.Nil(t, containerHostRelationships(hostRef, ""))
}
