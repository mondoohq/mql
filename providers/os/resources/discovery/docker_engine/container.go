// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker_engine

import (
	"context"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/id/containerid"
)

func (e *dockerEngineDiscovery) containerList() ([]container.Summary, error) {
	dc, err := e.client()
	if err != nil {
		return nil, err
	}

	res, err := dc.ContainerList(context.Background(), client.ContainerListOptions{})
	if err != nil {
		return nil, err
	}
	return res.Items, nil
}

func (e *dockerEngineDiscovery) ListContainerShas() ([]string, error) {
	containers, err := e.containerList()
	if err != nil {
		return []string{}, err
	}

	containerShas := []string{}
	for i := range containers {
		containerShas = append(containerShas, containers[i].ID)
	}

	return containerShas, nil
}

type ContainerInfo struct {
	ID         string
	Name       string
	PlatformID string
	Running    bool
	Labels     map[string]string
	Arch       string
}

// will resolve name and id to a container id
func (e *dockerEngineDiscovery) ContainerInfo(name string) (ContainerInfo, error) {
	ci := ContainerInfo{}
	dc, err := e.client()
	if err != nil {
		return ci, err
	}

	res, err := dc.ContainerInspect(context.Background(), name, client.ContainerInspectOptions{})
	if err != nil {
		return ci, err
	}
	cdata := res.Container

	cName := cdata.Name
	cName = strings.TrimPrefix(cName, "/")
	if len(cName) == 0 {
		cName = containerid.ShortContainerID(cdata.ID)
	}

	ci.ID = cdata.ID
	ci.Name = cName
	ci.PlatformID = containerid.MondooContainerID(ci.ID)
	ci.Running = cdata.State.Running

	// fetch docker specific metadata
	labels := map[string]string{}
	labels["docker.io/container-id"] = cdata.ID
	labels["docker.io/image-name"] = cdata.Image
	labels["docker.io/names"] = cName

	ci.Labels = labels

	return ci, nil
}

type ImageInfo struct {
	ID         string
	Name       string
	PlatformID string
	Labels     map[string]string
	Arch       string
	// Size in megabytes
	Size int64
}

func (e *dockerEngineDiscovery) ImageInfo(name string) (ImageInfo, error) {
	ii := ImageInfo{}
	dc, err := e.client()
	if err != nil {
		return ii, err
	}

	res, err := dc.ImageInspect(context.Background(), name)
	if err != nil {
		return ii, err
	}

	switch res.Architecture {
	case "amd64":
		ii.Arch = "x86_64"
	}

	ii.Size = res.Size / 1024 / 1024

	labels := map[string]string{}
	labels["mondoo.com/image-id"] = res.ID
	labels["docker.io/tags"] = strings.Join(res.RepoTags, ",")
	labels["docker.io/digests"] = strings.Join(res.RepoDigests, ",")

	if len(res.RepoTags) > 0 {
		ii.Name = res.RepoTags[0] + "@"
	}
	ii.Name = ii.Name + containerid.ShortContainerImageID(res.ID)
	ii.ID = res.ID
	ii.Labels = labels
	ii.PlatformID = containerid.MondooContainerImageID(res.ID)
	return ii, nil
}

func (e *dockerEngineDiscovery) ListContainer() ([]*inventory.Asset, error) {
	dContainers, err := e.containerList()
	if err != nil {
		return nil, err
	}

	container := make([]*inventory.Asset, len(dContainers))
	for i, dContainer := range dContainers {
		asset := &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type: "docker-container",
					Host: dContainer.ID,
				},
			},
		}
		log.Debug().Str("container", dContainer.ID).Msg("discovered container")

		container[i] = asset
	}
	return container, nil
}

// DockerDisplayNames removes the leading slash of the internal docker name
// @see  https://github.com/moby/moby/issues/6705
func DockerDisplayNames(names []string) []string {
	if names == nil {
		return nil
	}

	displayNames := make([]string, len(names))
	for i := range names {
		displayNames[i] = strings.TrimLeft(names[i], "/")
	}

	return displayNames
}
