// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package container_registry

import (
	"context"
	"errors"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/os/connection/container/auth"
)

type Resolver struct {
	// NoStrictValidation deactivates the strict validation for container registry resolutions
	// cr://index.docker.io/mondoo/client would be converted index.docker.io/mondoo/client:latest
	// It is not the default behavior but is used by the docker resolver to resolve images
	NoStrictValidation bool
}

func (r *Resolver) Resolve(ctx context.Context, root *inventory.Asset, conf *inventory.Config, credsResolver vault.Resolver) ([]*inventory.Asset, error) {
	resolved := []*inventory.Asset{}

	opts, err := RemoteOptionsFromConfigOptions(conf)
	if err != nil {
		return nil, err
	}

	imageFetcher := NewImageLister(opts...)

	// check if the reference is an image
	// NOTE: we use strict validation here otherwise urls like cr://index.docker.io/mondoo/client are converted
	// to index.docker.io/mondoo/client:latest
	nameOpts := name.StrictValidation
	if r.NoStrictValidation {
		nameOpts = name.WeakValidation
	}

	ref, err := name.ParseReference(conf.Host, nameOpts)
	if err == nil {
		log.Debug().Str("image", conf.Host).Msg("detected container image in container registry")

		opts = append(opts, auth.AuthOption(ref.Name(), conf.Credentials))
		a, err := imageFetcher.GetImage(ref, conf.Credentials, opts...)
		if err != nil {
			return nil, err
		}
		// keep already set options, i.e. image paths
		if conf.Options != nil && a.Connections[0].Options == nil {
			a.Connections[0].Options = conf.Options
		}

		if conf.Insecure {
			for i := range a.Connections {
				c := a.Connections[i]
				c.Insecure = conf.Insecure
				c.Credentials = conf.Credentials
			}
		}

		return []*inventory.Asset{a}, nil
	}

	// okay, no image, lets check the repository
	repository := conf.Host
	log.Info().Str("registry", repository).Msg("fetch meta information from container registry")

	assetList, err := imageFetcher.ListImages(repository)
	if err != nil {
		log.Error().Err(err).Msg("could not fetch container images")
		return nil, err
	}

	for i := range assetList {
		a := assetList[i]
		log.Info().Str("name", a.Name).Str("image", a.Connections[0].Host+assetList[i].Connections[0].Path).Msg("resolved image")

		if conf.Insecure {
			for i := range a.Connections {
				c := a.Connections[i]
				c.Insecure = conf.Insecure
			}
		}
		resolved = append(resolved, a)
	}

	if len(resolved) == 0 {
		return nil, errors.New("could not find repository:" + repository)
	}

	return resolved, nil
}
