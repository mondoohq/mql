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
	labels["docker.io/image-name"] = dockerContainerImageName(cdata)
	labels["docker.io/names"] = cName
	// Inspect's Image is the ID of the image the container runs.
	if strings.HasPrefix(cdata.Image, "sha256:") {
		labels["mondoo.com/image-id"] = cdata.Image
	}

	ci.Labels = labels

	return ci, nil
}

// dockerContainerImageName is the image reference the container was created
// from (nginx:1.27), which inspect keeps in Config.Image; its Image field is
// the image ID.
func dockerContainerImageName(c container.InspectResponse) string {
	if c.Config != nil && c.Config.Image != "" {
		return c.Config.Image
	}
	return c.Image
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

// ListContainer lists the running containers as assets to connect to. host is
// the asset the containers were found on; when it is set and the daemon is on
// that machine, each container carries a relationship back to it, anchored on
// the docker.container resource that lists it (ADR 030). The host is named by
// all of its platform IDs, so it is found even when the daemon's host name is
// not the one the host's own scan recorded.
func (e *dockerEngineDiscovery) ListContainer(host *inventory.Asset) ([]*inventory.Asset, error) {
	dContainers, err := e.containerList()
	if err != nil {
		return nil, err
	}

	hostRef := e.localHostRef(host)
	container := make([]*inventory.Asset, len(dContainers))
	for i, dContainer := range dContainers {
		asset := &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type: "docker-container",
					Host: dContainer.ID,
				},
			},
			Relationships: containerHostRelationships(hostRef, dContainer.ID),
		}
		log.Debug().Str("container", dContainer.ID).Msg("discovered container")

		container[i] = asset
	}
	return container, nil
}

// localHostRef is the identity of host for a relationship, or nil when there
// is no host with platform IDs or the daemon is not on it: DOCKER_HOST or a
// docker context can point the client at another machine, whose containers do
// not run on the scanned host.
func (e *dockerEngineDiscovery) localHostRef(host *inventory.Asset) *inventory.Asset {
	if host == nil || len(host.GetPlatformIds()) == 0 || e.Client == nil || !isLocalDaemon(e.Client.DaemonHost()) {
		return nil
	}
	return &inventory.Asset{
		Id:          host.GetId(),
		Mrn:         host.GetMrn(),
		PlatformIds: host.GetPlatformIds(),
	}
}

// isLocalDaemon is whether the daemon address is on this machine: a unix
// socket or a Windows named pipe. A tcp or ssh address may be another machine.
func isLocalDaemon(daemonHost string) bool {
	return strings.HasPrefix(daemonHost, "unix://") || strings.HasPrefix(daemonHost, "npipe://")
}

// containerHostRelationships is the edge from a container back to the host
// that runs it, anchored on the host's docker.container resource for it, whose
// ID is the container's full ID. None without a host.
func containerHostRelationships(hostRef *inventory.Asset, containerID string) []*inventory.AssetRelationship {
	if hostRef == nil || containerID == "" {
		return nil
	}
	return []*inventory.AssetRelationship{{
		Asset:        hostRef,
		ResourceType: "docker.container",
		ResourceId:   containerID,
	}}
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
