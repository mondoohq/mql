// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package image

import (
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"go.mondoo.com/mql/providers/os/connection/container/auth"
)

func GetImageDescriptor(ref name.Reference, opts ...remote.Option) (*remote.Descriptor, error) {
	if len(opts) == 0 {
		opts = auth.DefaultOpts(ref.Name(), false)
	}
	return remote.Get(ref, opts...)
}

func LoadImageFromRegistry(ref name.Reference, opts ...remote.Option) (v1.Image, error) {
	if len(opts) == 0 {
		opts = auth.DefaultOpts(ref.Name(), false)
	}
	img, err := remote.Image(ref, opts...)
	if err != nil {
		if errors.Is(err, remote.ErrSchema1) {
			return nil, fmt.Errorf("the container image %q uses Docker schema1 manifests which are no longer supported, try upgrading the image to a newer version", ref.Name())
		}
		return nil, err
	}
	return img, nil
}
