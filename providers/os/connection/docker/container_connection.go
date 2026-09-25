// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/moby/moby/client"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/cli/tmp"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/container"
	"go.mondoo.com/mql/providers/os/connection/container/image"
	"go.mondoo.com/mql/providers/os/connection/dockerclient"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/ssh/cat"
	"go.mondoo.com/mql/providers/os/connection/tar"
	"go.mondoo.com/mql/providers/os/id/containerid"
	"go.mondoo.com/mql/providers/os/resources/discovery/container_registry"
	dockerDiscovery "go.mondoo.com/mql/providers/os/resources/discovery/docker_engine"
)

const (
	ContainerConnectionType shared.ConnectionType = "docker-container"
)

var _ shared.Connection = &ContainerConnection{}

type ContainerConnection struct {
	plugin.Connection
	asset *inventory.Asset

	Client    *client.Client
	container string
	Fs        *FS

	PlatformIdentifier   string
	PlatformArchitecture string
	// optional metadata to store additional information
	Metadata struct {
		Name   string
		Labels map[string]string
	}

	kind    string
	runtime string
}

func NewContainerConnection(id uint32, conf *inventory.Config, asset *inventory.Asset) (*ContainerConnection, error) {
	// expect unix shell by default
	dockerClient, err := GetDockerClient()
	if err != nil {
		return nil, err
	}

	// check if we are having a container
	inspectRes, err := dockerClient.ContainerInspect(context.Background(), conf.Host, client.ContainerInspectOptions{})
	if err != nil {
		return nil, errors.New("cannot find container " + conf.Host)
	}
	data := inspectRes.Container

	if !data.State.Running {
		return nil, errors.New("container " + data.ID + " is not running")
	}

	conn := &ContainerConnection{
		Connection: plugin.NewConnection(id, asset),
		asset:      asset,
		Client:     dockerClient,
		container:  conf.Host,
		kind:       "container",
		runtime:    "docker",
	}

	// this can later be used for containers build from scratch
	serverVersionRes, err := dockerClient.ServerVersion(context.Background(), client.ServerVersionOptions{})
	if err != nil {
		log.Debug().Err(err).Msg("docker> cannot get server version")
	} else {
		log.Debug().Interface("serverVersion", serverVersionRes).Msg("docker> server version")
		conn.PlatformArchitecture = serverVersionRes.Arch
	}

	conn.Fs = &FS{
		dockerClient: conn.Client,
		Container:    conn.container,
		Connection:   conn,
		catFS:        cat.New(conn),
	}
	return conn, nil
}

func GetDockerClient() (*client.Client, error) {
	// Route through the shared builder so we honor DOCKER_HOST *and* the active
	// docker CLI context (rootless / remote contexts), not just DOCKER_HOST.
	return dockerclient.NewDockerClient()
}

func (c *ContainerConnection) Name() string {
	return string(ContainerConnectionType)
}

func (c *ContainerConnection) Type() shared.ConnectionType {
	return ContainerConnectionType
}

func (c *ContainerConnection) Asset() *inventory.Asset {
	return c.asset
}

func (p *ContainerConnection) UpdateAsset(asset *inventory.Asset) {
	p.asset = asset
}

func (c *ContainerConnection) ContainerId() string {
	return c.container
}

func (c *ContainerConnection) Capabilities() shared.Capabilities {
	return shared.Capability_File | shared.Capability_RunCommand
}

func (c *ContainerConnection) FileInfo(path string) (shared.FileInfoDetails, error) {
	fs := c.FileSystem()
	afs := &afero.Afero{Fs: fs}
	stat, err := afs.Stat(path)
	if err != nil {
		return shared.FileInfoDetails{}, err
	}

	mode := stat.Mode()

	uid := int64(-1)
	gid := int64(-1)

	if stat, ok := stat.Sys().(*shared.FileInfo); ok {
		uid = stat.Uid
		gid = stat.Gid
	}

	return shared.FileInfoDetails{
		Mode: shared.FileModeDetails{FileMode: mode},
		Size: stat.Size(),
		Uid:  uid,
		Gid:  gid,
	}, nil
}

func (c *ContainerConnection) FileSystem() afero.Fs {
	return c.Fs
}

func (c *ContainerConnection) RunCommand(command string) (*shared.Command, error) {
	log.Debug().Str("command", command).Msg("docker> run command")
	cmd := &Command{Client: c.Client, Container: c.container}
	res, err := cmd.Exec(command)
	// this happens, when we try to run /bin/sh in a container, which does not have it
	if err == nil && res.ExitStatus == 126 {
		output := ""
		var b []byte
		b, err = io.ReadAll(res.Stdout)
		if err == nil {
			output = string(b)
		}
		err = errors.New("could not execute command: " + output)
	}
	return res, err
}

func NewDockerEngineContainer(id uint32, conf *inventory.Config, asset *inventory.Asset) (shared.Connection, error) {
	// could be an image id/name, container id/name or a short reference to an image in docker engine
	ded, err := dockerDiscovery.NewDockerEngineDiscovery()
	if err != nil {
		return nil, err
	}

	ci, err := ded.ContainerInfo(conf.Host)
	if err != nil {
		return nil, err
	}

	platformID := containerid.MondooContainerID(ci.ID)
	shortID := containerid.ShortContainerImageID(ci.ID)

	asset.Name = ci.Name
	asset.PlatformIds = []string{platformID}

	if ci.Running {
		log.Debug().Msg("found running container " + ci.ID)
		conn, err := NewContainerConnection(id, &inventory.Config{Host: ci.ID}, asset)
		if err != nil {
			return nil, err
		}
		conn.PlatformIdentifier = platformID
		conn.Metadata.Name = shortID
		conn.Metadata.Labels = ci.Labels
		return conn, nil
	}

	log.Debug().Msg("found stopped container " + ci.ID)
	conn, err := NewSnapshotConnection(id, &inventory.Config{Host: ci.ID}, asset)
	if err != nil {
		return nil, err
	}
	conn.PlatformIdentifier = platformID
	conn.Metadata.Name = shortID
	conn.Metadata.Labels = ci.Labels
	// FIXME: DEPRECATED, remove in v12.0 vv
	// The DelayDiscovery flag should always be set from v12
	if conf.Options == nil || conf.Options[plugin.DISABLE_DELAYED_DISCOVERY_OPTION] == "" {
		conf.DelayDiscovery = true // Delay discovery, to make sure we don't directly download the image
	}
	// ^^
	return conn, nil
}

func NewContainerImageConnection(id uint32, conf *inventory.Config, asset *inventory.Asset) (*tar.Connection, error) {
	if conf.Options == nil {
		conf.Options = map[string]string{}
	}

	disableInmemoryCache := false
	if v, ok := conf.Options["disable-cache"]; ok {
		var err error
		disableInmemoryCache, err = strconv.ParseBool(v)
		if err != nil {
			return nil, err
		}
	}

	// FIXME: DEPRECATED, remove in v12.0 vv
	// The DelayDiscovery flag should always be set from v12
	if conf.Options[plugin.DISABLE_DELAYED_DISCOVERY_OPTION] == "" {
		conf.DelayDiscovery = true // Delay discovery, to make sure we don't directly download the image
	}
	// ^^

	// Try the local docker engine first. If the image isn't present (or docker isn't
	// available), pre-populate the asset metadata from the registry and then pull
	// from there. The registry pre-fill keeps asset.Name keyed by the top-level
	// manifest digest, which is stable across architectures for multi-arch tags.
	ded, dockerErr := dockerDiscovery.NewDockerEngineDiscovery()
	if dockerErr != nil {
		log.Debug().Err(dockerErr).Str("image", conf.Host).Msg("could not reach local docker engine, resolving image from registry instead")
		if err := fillAssetFromRegistry(asset, conf); err != nil {
			return nil, err
		}
		return container.NewRegistryImage(id, conf, asset)
	}

	ii, err := ded.ImageInfo(conf.Host)
	if err != nil {
		// The local lookup failed, so we treat conf.Host as a registry reference.
		// Surface the underlying reason: when the engine is unreachable (e.g. a
		// rootless socket not picked up, see FromDockerEnv) a bare image ID cannot
		// be resolved from a registry and the ensuing error is otherwise cryptic.
		log.Debug().Err(err).Str("image", conf.Host).Msg("image not found in local docker engine, resolving from registry instead")
		if err := fillAssetFromRegistry(asset, conf); err != nil {
			return nil, err
		}
		return container.NewRegistryImage(id, conf, asset)
	}

	labelImageId := ii.ID
	splitLabels := strings.Split(ii.Labels["docker.io/digests"], ",")
	if len(splitLabels) > 1 {
		labelImageIdFull := splitLabels[0]
		splitFullLabel := strings.Split(labelImageIdFull, "@")
		if len(splitFullLabel) > 1 {
			labelImageId = strings.Split(labelImageIdFull, "@")[1]
		}
	}

	// This is the image id that is used to pull the image from the registry.
	log.Debug().Msg("found docker engine image " + labelImageId)

	identifier := containerid.MondooContainerImageID(labelImageId)

	asset.PlatformIds = []string{identifier}
	asset.Name = ii.Name
	asset.Labels = ii.Labels

	// cache file locally
	var filename string
	tmpFile, err := tmp.File()
	if err != nil {
		return nil, err
	}
	filename = tmpFile.Name()

	conf.Options[tar.OPTION_FILE] = filename

	imageRef := ii.ID
	// if containerd store is enabled, the image reference needs to be the image name
	// instead of the image id, otherwise we will not be able to pull the image from the registry
	if kind := getImageStoreKind(); kind == "overlayfs" {
		imageRef = conf.Host
	}

	var tarConn *tar.Connection
	tarConn, err = tar.NewConnection(
		id,
		conf,
		asset,
		tar.WithFetchFn(func() (string, error) {
			img, err := image.LoadImageFromDockerEngine(imageRef, disableInmemoryCache)
			if err != nil {
				return filename, err
			}

			// Carry the architecture over from the image config, the same way the
			// registry path does. A tar connection has no command capability to ask
			// `uname -m`, so without this the asset reports an empty architecture.
			// This runs before platform detection reads the field back.
			if imgConfig, cfgErr := img.ConfigFile(); cfgErr == nil && imgConfig != nil {
				tarConn.PlatformArchitecture = imgConfig.Architecture
			}

			err = tar.StreamToTmpFile(mutate.Extract(img), tmpFile)
			if err != nil {
				_ = os.Remove(filename)
				return filename, err
			}
			return filename, nil
		}),
		tar.WithCloseFn(func() {
			log.Debug().Str("tar", filename).Msg("tar> remove temporary tar file on connection close")
			_ = os.Remove(filename)
		}))
	if err != nil {
		return nil, err
	}
	tarConn.PlatformIdentifier = identifier
	tarConn.Metadata.Name = ii.Name
	tarConn.Metadata.Labels = ii.Labels
	return tarConn, nil
}

// fillAssetFromRegistry pre-populates asset.Name, asset.PlatformIds, and asset.Labels
// from the registry-side view of conf.Host. The follow-up registry pull will then
// see those fields already set and skip its own (per-architecture) values, which
// keeps asset.Name stable across architectures for multi-arch tags. Errors are
// returned so the caller can bail out — matching the pre-refactor behavior where
// a registry resolution failure failed the connection attempt outright instead of
// silently falling through to a pull that would either fail with a less specific
// error or succeed with platform-specific (non-stable) identity.
func fillAssetFromRegistry(asset *inventory.Asset, conf *inventory.Config) error {
	resolved, err := (&container_registry.Resolver{NoStrictValidation: true}).Resolve(context.Background(), asset, conf, nil)
	if err != nil {
		return err
	}
	if len(resolved) == 0 {
		return errors.New("could not resolve container image: " + conf.Host)
	}
	asset.Name = resolved[0].Name
	asset.PlatformIds = resolved[0].PlatformIds
	asset.Labels = resolved[0].Labels
	return nil
}

func getImageStoreKind() string {
	cli, err := GetDockerClient()
	if err != nil {
		log.Warn().Err(err).Msg("docker> cannot create docker client")
		return "unknown"
	}

	infoRes, err := cli.Info(context.Background(), client.InfoOptions{})
	if err != nil {
		log.Warn().Err(err).Msg("docker> cannot get docker info")
		return "unknown"
	}

	return infoRes.Info.Driver
}

// FindDockerObjectConnectionType tries to find out what kind of connection we are dealing with, this can be either a
// 1. a container, referenced by name or id
// 2. a locally present image, referenced by tag or digest
// 3. a remote image, referenced by tag or digest
func FindDockerObjectConnectionType(target string) (string, error) {
	ded, err := dockerDiscovery.NewDockerEngineDiscovery()
	if err != nil {
		return "", err
	}

	if ded != nil {
		_, err = ded.ContainerInfo(target)
		if err == nil {
			return "docker-container", nil
		}
		_, err = ded.ImageInfo(target)
		if err == nil {
			return "docker-image", nil
		}
	}
	_, err = name.ParseReference(target, name.WeakValidation)
	if err == nil {
		return "docker-image", nil
	}

	return "", errors.New("could not find container or image " + target)
}
