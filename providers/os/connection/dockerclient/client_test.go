// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dockerclient_test

import (
	"testing"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/connection/dockerclient"
)

func newClientFromDockerEnv(t *testing.T) (*client.Client, error) {
	t.Helper()
	opts, err := dockerclient.FromDockerEnv()
	if err != nil {
		return nil, err
	}
	return client.New(opts...)
}

func TestDockerEnvParsing(t *testing.T) {
	// t.Setenv sets and auto-restores only the vars we touch, without disturbing
	// the rest of the environment. An empty value is equivalent to unset for our
	// resolution, which only checks for a non-empty DOCKER_HOST/DOCKER_CONTEXT.
	//
	// Isolate from the host's real ~/.docker so the "no DOCKER_HOST" default is
	// deterministic and doesn't pick up a machine-local docker context.
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	t.Setenv("DOCKER_CONTEXT", "")
	t.Setenv("DOCKER_HOST", "")

	// No DOCKER_HOST and no configured context falls back to the moby default socket.
	cli, err := newClientFromDockerEnv(t)
	assert.Nil(t, err)
	assert.Equal(t, "unix:///var/run/docker.sock", cli.DaemonHost())

	t.Setenv("DOCKER_HOST", "tcp://0.0.0.0:2375")
	cli, err = newClientFromDockerEnv(t)
	assert.Nil(t, err)
	assert.Equal(t, "tcp://0.0.0.0:2375", cli.DaemonHost())

	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	cli, err = newClientFromDockerEnv(t)
	assert.Nil(t, err)
	assert.Equal(t, "unix:///var/run/docker.sock", cli.DaemonHost())

	t.Setenv("DOCKER_HOST", "192.186.1.1")
	cli, err = newClientFromDockerEnv(t)
	assert.Nil(t, err)
	assert.Equal(t, "tcp://192.186.1.1:2375", cli.DaemonHost())

	t.Setenv("DOCKER_HOST", "http://192.186.1.1")
	_, err = newClientFromDockerEnv(t)
	assert.NotNil(t, err)

	t.Setenv("DOCKER_HOST", "tcp://192.186.1.1")
	cli, err = newClientFromDockerEnv(t)
	assert.Nil(t, err)
	assert.Equal(t, "tcp://192.186.1.1:2375", cli.DaemonHost())

	t.Setenv("DOCKER_HOST", "tcp://192.168.59.103:2377")
	cli, err = newClientFromDockerEnv(t)
	assert.Nil(t, err)
	assert.Equal(t, "tcp://192.168.59.103:2377", cli.DaemonHost())
}

// A DOCKER_HOST always wins over any configured context, matching the docker CLI.
func TestDockerHostWinsOverContext(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	t.Setenv("DOCKER_CONTEXT", "some-remote-context")
	t.Setenv("DOCKER_HOST", "tcp://192.168.59.103:2377")

	cli, err := newClientFromDockerEnv(t)
	assert.Nil(t, err)
	assert.Equal(t, "tcp://192.168.59.103:2377", cli.DaemonHost())
}

// An unknown/unresolvable context is non-fatal: we fall back to the default socket
// rather than error out.
func TestUnknownContextFallsBackToDefault(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	t.Setenv("DOCKER_CONTEXT", "does-not-exist")
	t.Setenv("DOCKER_HOST", "")

	cli, err := newClientFromDockerEnv(t)
	assert.Nil(t, err)
	assert.Equal(t, "unix:///var/run/docker.sock", cli.DaemonHost())
}
