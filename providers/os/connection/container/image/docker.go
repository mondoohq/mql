// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package image

import (
	"io"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"go.mondoo.com/mql/providers/os/connection/dockerclient"
)

type ShaReference struct {
	SHA string
}

func (r ShaReference) Name() string {
	return r.SHA
}

func (r ShaReference) String() string {
	return r.SHA
}

func (r ShaReference) Context() name.Repository {
	return name.Repository{}
}

func (r ShaReference) Identifier() string {
	return r.SHA
}

func (r ShaReference) Scope(scope string) string {
	return ""
}

func LoadImageFromDockerEngine(sha string, disableBuffer bool) (v1.Image, error) {
	// Inject a context-aware docker client so rootless / remote docker contexts
	// are reached. daemon.Image otherwise defaults to client.FromEnv, which only
	// honors DOCKER_HOST and the compiled-in default socket.
	dc, err := dockerclient.NewDockerClient()
	if err != nil {
		return nil, err
	}
	// Buffer the `docker save` stream to a temporary file, not to memory.
	//
	// daemon.Image defaults to the in-memory opener, which reads the whole save
	// stream with io.ReadAll and keeps it alive for the lifetime of the image.
	// That single []byte holds the complete image, so the provider process grows
	// with the image and the Go heap target doubles it again. A 847 MB image cost
	// about 2.2 GB of peak RSS, which the container runtime turns into an OOM kill.
	//
	// The file-backed opener still runs exactly one `docker save`, so it does not
	// pay the repeated-save cost of the unbuffered opener.
	opts := []daemon.Option{daemon.WithClient(dc), daemon.WithFileBufferedOpener()}
	if disableBuffer {
		opts = append(opts, daemon.WithUnbufferedOpener())
	}
	img, err := daemon.Image(&ShaReference{SHA: strings.ReplaceAll(sha, "sha256:", "")}, opts...)
	if err != nil {
		return nil, err
	}

	return img, nil
}

func WriteCompressedTarImageToFile(img v1.Image, digest string, f *os.File) error {
	ref, err := name.ParseReference(digest, name.WeakValidation)
	if err != nil {
		return err
	}

	err = tarball.Write(ref, img, f)
	if err != nil {
		return err
	}

	// Rewind, to later read the complete file for uncompress
	_, err = f.Seek(0, io.SeekStart)
	return err
}
