// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar_test

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

const (
	alpineImage         = "alpine:3.14"
	alpineContainerPath = "./alpine-container.tar"

	centosImage         = "centos:7"
	centosContainerPath = "./centos-container.tar"
)

func TestTarCommand(t *testing.T) {
	err := cacheAlpine()
	require.NoError(t, err, "should create tar without error")

	c, err := tar.NewConnection(0, &inventory.Config{
		Type: "tar",
		Options: map[string]string{
			tar.OPTION_FILE: alpineContainerPath,
		},
	}, &inventory.Asset{})
	assert.Equal(t, nil, err, "should create tar without error")

	cmd, err := c.RunCommand("ls /")
	assert.Nil(t, err)
	if assert.NotNil(t, cmd) {
		assert.Equal(t, nil, err, "should execute without error")
		assert.Equal(t, -1, cmd.ExitStatus, "command should not be executed")
		stdoutContent, _ := io.ReadAll(cmd.Stdout)
		assert.Equal(t, "", string(stdoutContent), "output should be correct")
		stderrContent, _ := io.ReadAll(cmd.Stdout)
		assert.Equal(t, "", string(stderrContent), "output should be correct")
	}
}

func TestPlatformIdentifier(t *testing.T) {
	err := cacheAlpine()
	require.NoError(t, err, "should create tar without error")

	conn, err := tar.NewConnection(0, &inventory.Config{
		Type: "tar",
		Options: map[string]string{
			tar.OPTION_FILE: alpineContainerPath,
		},
	}, &inventory.Asset{})
	require.NoError(t, err)
	platformId, err := conn.Identifier()
	require.NoError(t, err)
	assert.True(t, len(platformId) > 0)
	assert.True(t, strings.HasPrefix(platformId, "//platformid.api.mondoo.app/runtime/tar/hash/"))
}

func cacheAlpine() error {
	return cacheImageToTar(alpineImage, alpineContainerPath)
}

func cacheCentos() error {
	return cacheImageToTar(centosImage, centosContainerPath)
}

func cacheImageToTar(source string, filename string) error {
	// check if the cache is already there
	_, err := os.Stat(filename)
	if err == nil {
		return nil
	}

	tag, err := name.NewTag(source, name.WeakValidation)
	if err != nil {
		return err
	}

	auth, err := authn.DefaultKeychain.Resolve(tag.Registry)
	if err != nil {
		return err
	}

	img, err := remote.Image(tag, remote.WithAuth(auth), remote.WithTransport(http.DefaultTransport))
	if err != nil {
		return err
	}

	// it is important that we extract the image here, since tar does not understand the OCI image
	// format and its layers
	w, err := os.Create(filename)
	if err != nil {
		return err
	}

	return tar.StreamToTmpFile(mutate.Extract(img), w)
}

// A tar that cannot be fetched must fail the connection. It used to be logged
// and the scan went on over an empty filesystem: no platform, no packages.
func TestFetchFailureIsAnError(t *testing.T) {
	require.NoError(t, cacheAlpine())
	c, err := tar.NewConnection(0, &inventory.Config{
		Type:    "tar",
		Options: map[string]string{tar.OPTION_FILE: alpineContainerPath},
	}, &inventory.Asset{}, tar.WithFetchFn(func() (string, error) {
		return "", errors.New("invalid container name or ID: value is empty")
	}))
	require.NoError(t, err)
	assert.ErrorContains(t, c.Fetch(), "value is empty")
	assert.ErrorContains(t, c.Fetch(), "value is empty", "the error stays")
}
