// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/dockerclient"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/containerid"
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

	defer cl.Close()

	imageListRes, err := cl.ImageList(context.Background(), client.ImageListOptions{})
	if err != nil {
		return nil, classifyDockerError(err)
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

	defer cl.Close()

	dContainers, err := listAllDockerContainers(context.Background(), cl)
	if err != nil {
		return nil, classifyDockerError(err)
	}

	containers := make([]any, len(dContainers))
	for i, dContainer := range dContainers {
		c, err := newDockerContainer(p.MqlRuntime, dContainer)
		if err != nil {
			return nil, err
		}
		containers[i] = c
	}

	return containers, nil
}

// newDockerContainer creates the docker.container for one entry of the
// daemon's container listing.
func newDockerContainer(runtime *plugin.Runtime, dContainer container.Summary) (*mqlDockerContainer, error) {
	labels := make(map[string]any, len(dContainer.Labels))
	for key, value := range dContainer.Labels {
		labels[key] = value
	}

	names := []any{}
	for _, name := range dContainer.Names {
		names = append(names, strings.TrimPrefix(name, "/"))
	}

	o, err := CreateResource(runtime, "docker.container", map[string]*llx.RawData{
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

	c := o.(*mqlDockerContainer)
	c.endpoints = dockerContainerEndpoints(dContainer)
	c.volumeNames = dockerContainerVolumeNames(dContainer)
	return c, nil
}

// initDockerContainer resolves `docker.container` with no argument to the
// container being scanned, and `docker.container(id)` to the container with
// that ID, unique ID prefix, or name.
func initDockerContainer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// A listing creates the resource with all its fields.
	if len(args) > 1 {
		return args, nil, nil
	}

	var want string
	if len(args) == 1 {
		raw, ok := args["id"]
		if !ok {
			return args, nil, nil
		}
		id, ok := raw.Value.(string)
		if !ok || strings.TrimSpace(id) == "" {
			return nil, nil, errors.New("docker.container needs a container ID or name")
		}
		want = strings.TrimSpace(id)
	} else {
		want = scannedDockerContainerID(runtime)
		if want == "" {
			return nil, nil, llx.NotApplicable(errors.New("docker.container needs a container ID or name unless the asset is a Docker container"))
		}
	}

	d, err := NewResource(runtime, "docker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	all := d.(*mqlDocker).GetContainers()
	if all.Error != nil {
		return nil, nil, all.Error
	}
	containers := make([]*mqlDockerContainer, 0, len(all.Data))
	for _, x := range all.Data {
		if c, ok := x.(*mqlDockerContainer); ok {
			containers = append(containers, c)
		}
	}
	c, err := matchDockerContainer(containers, want)
	if err != nil {
		return nil, nil, err
	}
	return nil, c, nil
}

// matchDockerContainer finds the container with this ID, else the only one
// whose ID starts with it, else the one with this name, as the docker CLI
// does.
func matchDockerContainer(containers []*mqlDockerContainer, want string) (*mqlDockerContainer, error) {
	for _, c := range containers {
		if c.Id.Data == want {
			return c, nil
		}
	}
	var prefixed []*mqlDockerContainer
	for _, c := range containers {
		if strings.HasPrefix(c.Id.Data, want) {
			prefixed = append(prefixed, c)
		}
	}
	if len(prefixed) == 1 {
		return prefixed[0], nil
	}
	if len(prefixed) > 1 {
		return nil, fmt.Errorf("docker.container %q matches %d containers", want, len(prefixed))
	}
	for _, c := range containers {
		for _, n := range c.Names.Data {
			if n == want {
				return c, nil
			}
		}
	}
	return nil, llx.NotFound(fmt.Errorf("docker.container %q not found", want))
}

// scannedDockerContainerID is the ID of the container the asset is, when the
// scan reaches a Docker container, running or exported; else "".
func scannedDockerContainerID(runtime *plugin.Runtime) string {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return ""
	}
	switch conn.Type() {
	case shared.Type_DockerContainer, shared.Type_DockerSnapshot:
	default:
		return ""
	}
	for _, pid := range conn.Asset().GetPlatformIds() {
		if id, ok := containerid.ContainerIDFromPlatformID(pid); ok {
			return id
		}
	}
	return ""
}

type mqlDockerEngineInternal struct {
	lock        sync.Mutex
	infoFetched bool
	infoVal     system.Info
	infoErr     error
}

// initDockerEngine resolves a bare `docker.engine` through docker's accessor,
// which fills it.
func initDockerEngine(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	d, err := NewResource(runtime, "docker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	e := d.(*mqlDocker).GetEngine()
	if e.Error != nil {
		return nil, nil, e.Error
	}
	return nil, e.Data, nil
}

// engine reads the daemon's version information.
func (p *mqlDocker) engine() (*mqlDockerEngine, error) {
	cl, err := dockerClient(p.MqlRuntime)
	if err != nil {
		return nil, err
	}
	defer cl.Close()

	v, err := cl.ServerVersion(context.Background(), client.ServerVersionOptions{})
	if err != nil {
		return nil, classifyDockerError(err)
	}
	componentNames := make([]string, 0, len(v.Components))
	for _, c := range v.Components {
		componentNames = append(componentNames, c.Name)
	}
	o, err := CreateResource(p.MqlRuntime, "docker.engine", map[string]*llx.RawData{
		"name":       llx.StringData(dockerEngineName(componentNames)),
		"version":    llx.StringData(v.Version),
		"apiVersion": llx.StringData(v.APIVersion),
		"os":         llx.StringData(v.Os),
		"arch":       llx.StringData(v.Arch),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlDockerEngine), nil
}

func (e *mqlDockerEngine) hostname() (string, error) {
	info, err := e.info()
	if err != nil {
		return "", err
	}
	return info.Name, nil
}

func (e *mqlDockerEngine) operatingSystem() (string, error) {
	info, err := e.info()
	if err != nil {
		return "", err
	}
	return info.OperatingSystem, nil
}

// info reads the engine's system information, once.
func (e *mqlDockerEngine) info() (system.Info, error) {
	e.lock.Lock()
	defer e.lock.Unlock()
	if e.infoFetched {
		return e.infoVal, e.infoErr
	}
	e.infoFetched = true
	cl, err := dockerClient(e.MqlRuntime)
	if err != nil {
		e.infoErr = err
		return e.infoVal, e.infoErr
	}
	defer cl.Close()
	res, err := cl.Info(context.Background(), client.InfoOptions{})
	if err != nil {
		e.infoErr = classifyDockerError(err)
		return e.infoVal, e.infoErr
	}
	e.infoVal = res.Info
	return e.infoVal, nil
}

// id is fixed: a docker resource reaches one engine.
func (e *mqlDockerEngine) id() (string, error) {
	return "docker.engine", nil
}

// dockerEngineName names the engine from the components its version lists:
// Podman's Docker-compatible API reports a "Podman Engine" component.
func dockerEngineName(components []string) string {
	for _, c := range components {
		if strings.HasPrefix(strings.ToLower(c), "podman") {
			return "Podman"
		}
	}
	return "Docker"
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
