// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker_engine

import (
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"go.mondoo.com/mql/providers/os/fsutil"
	"go.mondoo.com/mql/providers/os/id/containerid"
)

func platformID(filename string) (string, error) {
	var identifier string
	// try to determine if the tar is a container image
	img, iErr := tarball.ImageFromPath(filename, nil)
	if iErr == nil {
		hash, err := img.Digest()
		if err != nil {
			return "", err
		}
		identifier = containerid.MondooContainerImageID(hash.String())
	} else {
		hash, err := fsutil.LocalFileSha256(filename)
		if err != nil {
			return "", err
		}
		identifier = "//platformid.api.mondoo.app/runtime/tar/hash/" + hash
	}
	return identifier, nil
}
