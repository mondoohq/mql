// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/dockerclient"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// Older daemons (API < 1.40 or so, e.g. docker.io on Ubuntu 16.04 and 18.04)
// report a dangling image with these placeholders instead of empty lists. They
// are not references anyone can pull, so the image has no tags or digests.
const (
	dockerNoneTag    = "<none>:<none>"
	dockerNoneDigest = "<none>@<none>"
)

// dockerImageRefs converts an image's tags or digests, dropping the
// placeholder an older daemon reports for a dangling image.
func dockerImageRefs(refs []string, placeholder string) []any {
	res := []any{}
	for _, ref := range refs {
		if ref == placeholder {
			continue
		}
		res = append(res, ref)
	}
	return res
}

type dockerContainerLister interface {
	ContainerList(ctx context.Context, options client.ContainerListOptions) (client.ContainerListResult, error)
}

// listAllDockerContainers lists every container the daemon knows, not just the
// running ones. The Docker API's default (and `docker ps`) leaves out created,
// exited and dead containers, which would let a check over the host's
// containers pass while a stopped one is still there.
func listAllDockerContainers(ctx context.Context, cl dockerContainerLister) ([]container.Summary, error) {
	res, err := cl.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}
	return res.Items, nil
}

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

		tags := dockerImageRefs(dImg.RepoTags, dockerNoneTag)
		digests := dockerImageRefs(dImg.RepoDigests, dockerNoneDigest)

		r, err := CreateResource(p.MqlRuntime, "docker.image", map[string]*llx.RawData{
			"id":          llx.StringData(dImg.ID),
			"size":        llx.IntData(dImg.Size),
			"repoDigests": llx.ArrayData(digests, types.String),
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

	dContainers, err := listAllDockerContainers(context.Background(), cl)
	if err != nil {
		return nil, err
	}

	containers := make([]any, len(dContainers))

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

		containers[i] = o.(*mqlDockerContainer)
	}

	return containers, nil
}

// running is the anchor for the container as its own asset (ADR 031).
//
// It answers with the anchor and nothing else - identity, never how to reach
// the thing - because this value persists into recordings and upstream (ADR
// 030). The connection is asked for at connect time, in MqlAsset.
//
// A container that is not running has nothing to connect to, so it answers
// null: `docker.containers.where(running == null)` is how you ask which ones
// are down.
func (p *mqlDockerContainer) running() (*llx.AssetValue, error) {
	if !p.isRunning() {
		p.Running.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return &llx.AssetValue{
		ResourceType: p.MqlName(),
		ResourceId:   p.MqlID(),
	}, nil
}

// MqlAsset implements plugin.AssetSource: how to reach the container behind the
// `running` anchor. The os provider serves containers through its own
// `docker-container` connector, so this is a local connect - no other provider
// is involved.
func (p *mqlDockerContainer) MqlAsset() (*inventory.Asset, error) {
	if !p.isRunning() {
		return nil, nil
	}

	name := p.Id.Data
	if names := p.Names.Data; len(names) > 0 {
		if first, ok := names[0].(string); ok && first != "" {
			name = first
		}
	}

	return &inventory.Asset{
		Name: name,
		Connections: []*inventory.Config{{
			Type: string(shared.Type_DockerContainer),
			Host: p.Id.Data,
		}},
	}, nil
}

// isRunning reports whether the container is up. Docker's `state` is the
// machine-readable one of created/running/paused/restarting/exited/dead, so
// only one value means there is a process to connect to.
func (p *mqlDockerContainer) isRunning() bool {
	return p.State.Data == "running"
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
	// Negotiate up front so a daemon older than the client library's minimum
	// API version is still reachable. See dockerclient.NewNegotiatedDockerClient.
	cl, err := dockerclient.NewNegotiatedDockerClient(context.Background())
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
