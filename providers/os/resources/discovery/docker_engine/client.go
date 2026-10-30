// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker_engine

import (
	"github.com/cockroachdb/errors"
	"github.com/moby/moby/client"
	"go.mondoo.com/mql/providers/os/connection/dockerclient"
)

// TODO: this implementation needs to be merged with motorcloud/docker
func NewDockerEngineDiscovery() (*dockerEngineDiscovery, error) {
	dc, err := dockerclient.NewDockerClient()
	if err != nil {
		return nil, err
	}

	return &dockerEngineDiscovery{
		Client: dc,
	}, nil
}

type dockerEngineDiscovery struct {
	Client *client.Client
}

func (e *dockerEngineDiscovery) client() (*client.Client, error) {
	if e.Client != nil {
		return e.Client, nil
	}
	return nil, errors.New("docker client not initialized")
}
