// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker_engine

import (
	"context"
	"os"

	"github.com/cockroachdb/errors"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/os/resources/discovery/container_registry"
	"go.mondoo.com/mql/utils/stringx"
)

const (
	DiscoveryContainerRunning = "container"
	DiscoveryContainerImages  = "container-images"
)

type Resolver struct{}

// func (r *Resolver) Resolve(ctx context.Context, root *inventory.Asset, conf *inventory.Config, credsResolver vault.Resolver, sfn common.QuerySecretFn, userIdDetectors ...providers.PlatformIdDetector) ([]*inventory.Asset, error) {
func (r *Resolver) Resolve(ctx context.Context, root *inventory.Asset, conf *inventory.Config, credsResolver vault.Resolver) ([]*inventory.Asset, error) {
	if conf == nil {
		return nil, errors.New("no provider configuration found")
	}

	// check if we have a tar as input
	// detect if the tar is a container image format -> container image
	// or a container snapshot format -> container snapshot
	if conf.Type == "tar" {

		if conf.Options == nil || conf.Options["file"] == "" {
			return nil, errors.New("could not find the tar file")
		}

		filename := conf.Options["file"]

		// check if we are pointing to a local tar file
		_, err := os.Stat(filename)
		if err != nil {
			return nil, errors.New("could not find the tar file: " + filename)
		}

		// Tar container can be an image or a snapshot
		resolvedAsset := &inventory.Asset{
			Name:        filename,
			Connections: []*inventory.Config{conf},
			Platform: &inventory.Platform{
				Kind:    "container-image",
				Runtime: "docker-image",
			},
			State: inventory.State_STATE_ONLINE,
		}

		// determine platform identifier
		identifier, err := platformID(filename)
		if err != nil {
			return nil, err
		}

		resolvedAsset.PlatformIds = []string{identifier}

		return []*inventory.Asset{resolvedAsset}, nil
	}

	ded, dockerEngErr := NewDockerEngineDiscovery()
	// we do not fail here, since we pull the image from upstream if its is an image without the need for docker

	if conf.Type == "docker-container" {
		if dockerEngErr != nil {
			return nil, errors.Wrap(dockerEngErr, "cannot connect to docker engine to fetch the container")
		}
		resolvedAsset, err := r.container(ctx, root, conf, ded)
		if err != nil {
			return nil, err
		}

		return []*inventory.Asset{resolvedAsset}, nil
	}

	if conf.Type == "docker-image" {
		// NOTE, we ignore dockerEngErr here since we fallback to pulling the images directly
		// resolvedAssets, err := r.images(ctx, root, conf, ded, credsResolver, sfn)
		resolvedAssets, err := r.images(ctx, root, conf, ded, credsResolver)
		if err != nil {
			return nil, err
		}
		return resolvedAssets, nil
	}

	// check if we should do a discovery
	if conf.Host == "" {
		return DiscoverDockerEngineAssets(conf)
	}

	// if we are here, the user has not specified the direct target, we need to search for it
	// could be an image id/name, container id/name or a short reference to an image in docker engine
	// 1. check if we have a container id
	//    check if the container is running -> docker engine
	//    check if the container is stopped -> container snapshot
	// 3. check if we have an image id -> container image
	// 4. check if we have a descriptor for a registry -> container image
	log.Debug().Str("docker", conf.Host).Msg("try to resolve the container or image source")

	if dockerEngErr == nil {
		containerAsset, err := r.container(ctx, root, conf, ded)
		if err == nil {
			return []*inventory.Asset{containerAsset}, nil
		}
	}

	// containerImageAssets, err := r.images(ctx, root, conf, ded, credsResolver, sfn)
	containerImageAssets, err := r.images(ctx, root, conf, ded, credsResolver)
	if err == nil {
		return containerImageAssets, nil
	}

	// if we reached here, we assume we have a name of an image or container from a registry
	return nil, errors.Wrap(err, "could not find the container reference")
}

func (k *Resolver) container(ctx context.Context, root *inventory.Asset, conf *inventory.Config, ded *dockerEngineDiscovery) (*inventory.Asset, error) {
	ci, err := ded.ContainerInfo(conf.Host)
	if err != nil {
		return nil, err
	}

	conf.Type = "docker-container"

	// TODO: how do we know we're not connecting to docker over
	// the network and LOCAL_OS is correct
	relatedAssets := []*inventory.Asset{
		{
			Connections: []*inventory.Config{
				{
					Type: "local",
				},
			},
		},
	}

	return &inventory.Asset{
		Name:        ci.Name,
		Connections: []*inventory.Config{conf},
		PlatformIds: []string{ci.PlatformID},
		Platform: &inventory.Platform{
			Kind:    "container",
			Runtime: "docker-container",
		},
		State:         inventory.State_STATE_ONLINE,
		Labels:        ci.Labels,
		RelatedAssets: relatedAssets,
	}, nil
}

// func (k *Resolver) images(ctx context.Context, root *inventory.Asset, conf *inventory.Config, ded *dockerEngineDiscovery, credsResolver vault.Resolver, sfn common.QuerySecretFn) ([]*inventory.Asset, error) {
func (k *Resolver) images(ctx context.Context, root *inventory.Asset, conf *inventory.Config, ded *dockerEngineDiscovery, credsResolver vault.Resolver) ([]*inventory.Asset, error) {
	// if we have a docker engine available, try to fetch it from there
	if ded != nil {
		ii, err := ded.ImageInfo(conf.Host)
		if err == nil {
			conf.Type = "docker-image"
			return []*inventory.Asset{{
				Name:        ii.Name,
				Connections: []*inventory.Config{conf},
				PlatformIds: []string{ii.PlatformID},
				Platform: &inventory.Platform{
					Kind:    "container-image",
					Runtime: "docker-image",
				},
				State:  inventory.State_STATE_ONLINE,
				Labels: ii.Labels,
			}}, nil
		}

	}

	// otherwise try to fetch the image from upstream
	log.Debug().Msg("try to download the image from docker registry")
	_, err := name.ParseReference(conf.Host, name.WeakValidation)
	if err != nil {
		return nil, err
	}

	// switch to container registry resolver since docker is not installed
	rr := container_registry.Resolver{
		NoStrictValidation: true,
	}
	return rr.Resolve(ctx, root, conf, credsResolver)
}

func DiscoverDockerEngineAssets(conf *inventory.Config) ([]*inventory.Asset, error) {
	log.Debug().Msg("start discovery for docker engine")
	// we use generic `container` and `container-images` options to avoid the requirement for the user to know if
	// the system is using docker or podman locally
	assetList := []*inventory.Asset{}

	if conf.Discover == nil {
		return assetList, nil
	}

	// discover running container: container
	if stringx.Contains(conf.Discover.Targets, "all") || stringx.Contains(conf.Discover.Targets, DiscoveryContainerRunning) {
		ded, err := NewDockerEngineDiscovery()
		if err != nil {
			return nil, err
		}

		containerAssets, err := ded.ListContainer()
		if err != nil {
			return nil, err
		}

		log.Info().Int("container", len(containerAssets)).Msg("running container search completed")
		assetList = append(assetList, containerAssets...)
	}

	// discover container images: container-images
	if stringx.Contains(conf.Discover.Targets, "all") || stringx.Contains(conf.Discover.Targets, DiscoveryContainerImages) {
		ded, err := NewDockerEngineDiscovery()
		if err != nil {
			return nil, err
		}

		containerImageAssets, err := ded.ListImages()
		if err != nil {
			return nil, err
		}
		log.Info().Int("images", len(containerImageAssets)).Msg("running container images search completed")
		assetList = append(assetList, containerImageAssets...)
	}
	return assetList, nil
}
