// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/moby/moby/client"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/os/connection/dockerclient"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/types"
)

func (p *mqlDocker) images() ([]any, error) {
	cl, err := dockerClient(p.MqlRuntime)
	if err != nil {
		return nil, err
	}

	imageListRes, err := cl.ImageList(context.Background(), client.ImageListOptions{})
	if err != nil {
		return nil, err
	}
	dImages := imageListRes.Items

	imgs := make([]any, len(dImages))
	for i, dImg := range dImages {
		labels := make(map[string]any)
		for key := range dImg.Labels {
			labels[key] = dImg.Labels[key]
		}

		tags := []any{}
		for i := range dImg.RepoTags {
			tags = append(tags, dImg.RepoTags[i])
		}

		r, err := CreateResource(p.MqlRuntime, "docker.image", map[string]*llx.RawData{
			"id":          llx.StringData(dImg.ID),
			"size":        llx.IntData(dImg.Size),
			"repoDigests": llx.ArrayData(llx.TArr2Raw(dImg.RepoDigests), types.String),
			"labels":      llx.MapData(labels, types.String),
			"tags":        llx.ArrayData(tags, types.String),
		})
		if err != nil {
			return nil, err
		}

		imgs[i] = r.(*mqlDockerImage)
	}

	return imgs, nil
}

func (p *mqlDocker) containers() ([]any, error) {
	cl, err := dockerClient(p.MqlRuntime)
	if err != nil {
		return nil, err
	}

	containerListRes, err := cl.ContainerList(context.Background(), client.ContainerListOptions{})
	if err != nil {
		return nil, err
	}
	dContainers := containerListRes.Items

	container := make([]any, len(dContainers))

	for i, dContainer := range dContainers {
		labels := make(map[string]any)
		for key := range dContainer.Labels {
			labels[key] = dContainer.Labels[key]
		}

		names := []any{}
		for i := range dContainer.Names {
			name := dContainer.Names[i]
			name = strings.TrimPrefix(name, "/")
			names = append(names, name)
		}

		/*
			FIXME: ??? not used?
			conn, err := connection.NewDockerEngineContainer(dContainer.ID)
			if err != nil {
				return nil, err
			}
		*/

		o, err := CreateResource(p.MqlRuntime, "docker.container", map[string]*llx.RawData{
			"id":      llx.StringData(dContainer.ID),
			"image":   llx.StringData(dContainer.Image),
			"imageid": llx.StringData(dContainer.ImageID),
			"command": llx.StringData(dContainer.Command),
			"state":   llx.StringData(string(dContainer.State)),
			"status":  llx.StringData(dContainer.Status),
			"labels":  llx.MapData(labels, types.String),
			"names":   llx.ArrayData(names, types.String),
		})
		if err != nil {
			return nil, err
		}

		container[i] = o.(*mqlDockerContainer)
	}

	return container, nil
}

func (p *mqlDockerContainer) os() (*mqlOsLinux, error) {
	res, err := CreateResource(p.MqlRuntime, "os.linux", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOsLinux), nil
}

func (p *mqlDockerImage) id() (string, error) {
	return p.Id.Data, nil
}

func (p *mqlDockerContainer) id() (string, error) {
	return p.Id.Data, nil
}

func (p *mqlDockerContainer) hostConfig() (any, error) {
	cl, err := dockerClient(p.MqlRuntime)
	if err != nil {
		return nil, err
	}

	res, err := cl.ContainerInspect(context.Background(), p.Id.Data, client.ContainerInspectOptions{})
	if err != nil {
		return nil, err
	}

	return convert.JsonToDict(res.Container.HostConfig)
}

// dockerClient builds a client from the provider process's own environment, so
// it always reaches the daemon on the machine running mql. That is the asset's
// daemon only when the connection is local or docker-backed; on any other
// transport the resource would report the scanner's images and containers as
// the scanned host's.
func dockerClient(runtime *plugin.Runtime) (*client.Client, error) {
	if err := checkDockerDaemonIsTheAssets(runtime); err != nil {
		return nil, err
	}

	// Honor DOCKER_HOST and the active docker CLI context (rootless / remote),
	// not just DOCKER_HOST. See dockerclient.FromDockerEnv for the why.
	cl, err := dockerclient.NewDockerClient()
	if err != nil {
		return nil, err
	}
	log.Debug().Msgf("docker client> negotiated API version %s", cl.ClientVersion())
	return cl, nil
}

// dockerLocalDaemonConnections are the connections whose asset is served by the
// daemon mql itself talks to. Everything else reaches the host over a transport
// the docker client knows nothing about.
var dockerLocalDaemonConnections = map[shared.ConnectionType]struct{}{
	shared.Type_Local:             {},
	shared.Type_DockerContainer:   {},
	shared.Type_DockerImage:       {},
	shared.Type_DockerSnapshot:    {},
	shared.Type_DockerFile:        {},
	shared.Type_DockerRegistry:    {},
	shared.Type_ContainerRegistry: {},
	shared.Type_RegistryImage:     {},
	"mock":                        {},
}

func checkDockerDaemonIsTheAssets(runtime *plugin.Runtime) error {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return nil
	}
	if _, ok := dockerLocalDaemonConnections[conn.Type()]; ok {
		return nil
	}
	return fmt.Errorf(
		"the docker resource reads the Docker daemon on the machine running mql, which is not the daemon of this %s connection",
		conn.Type())
}
