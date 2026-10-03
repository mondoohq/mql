// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package container_test

import (
	"io"
	"net/http"
	"os"
	"regexp"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/container"
	"go.mondoo.com/mql/providers/os/connection/container/image"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

const (
	alpineImage         = "alpine:3.19"
	alpineContainerPath = "./alpine-container.tar"

	centosImage         = "centos:7"
	centosContainerPath = "./centos-container.tar"
)

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

	// Download to a temporary file and only move it into place once it is
	// complete. Writing straight to filename means an interrupted pull (a
	// truncated layer, a killed run) leaves a partial tar behind, and the
	// os.Stat check above then treats that corrupt file as a valid cache on
	// every subsequent run. The failure that produces is "unexpected EOF" from
	// whatever later tries to read the tar, which points nowhere near the
	// download that actually failed.
	//
	// The temporary file deliberately sits next to its destination rather than
	// in os.TempDir(): a same-directory rename is atomic and cannot land
	// cross-volume, which is what would make os.Rename fail on Windows.
	tmp := filename + ".partial"
	if err := tarball.WriteToFile(tmp, tag, img); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, filename)
}

func cacheAlpine() error {
	return cacheImageToTar(alpineImage, alpineContainerPath)
}

func cacheCentos() error {
	return cacheImageToTar(centosImage, centosContainerPath)
}

type dockerConnTest struct {
	name     string
	conn     *tar.Connection
	testfile string
}

func TestNewImageConnection_DelayDiscovery(t *testing.T) {
	ref, err := name.ParseReference(alpineImage, name.WeakValidation)
	require.NoError(t, err)

	img, err := image.LoadImageFromRegistry(ref)
	require.NoError(t, err)

	inv := &inventory.Config{Options: map[string]string{}}
	_, err = container.NewImageConnection(1, inv, &inventory.Asset{}, img, ref)
	require.NoError(t, err)
	assert.True(t, inv.DelayDiscovery)
}

func TestNewImageConnection_DisableDelayDiscovery(t *testing.T) {
	ref, err := name.ParseReference(alpineImage, name.WeakValidation)
	require.NoError(t, err)

	img, err := image.LoadImageFromRegistry(ref)
	require.NoError(t, err)

	inv := &inventory.Config{Options: map[string]string{plugin.DISABLE_DELAYED_DISCOVERY_OPTION: "true"}}
	_, err = container.NewImageConnection(1, inv, &inventory.Asset{}, img, ref)
	require.NoError(t, err)
	assert.False(t, inv.DelayDiscovery)
}

func TestNewImageConnectionSetsOciTarFile(t *testing.T) {
	t.Run("do not include oci does not set oci tar file opt", func(t *testing.T) {
		err := cacheAlpine()
		require.NoError(t, err, "should create tar without error")

		ref, err := name.ParseReference(alpineImage, name.WeakValidation)
		require.NoError(t, err)

		img, err := tarball.ImageFromPath(alpineContainerPath, nil)
		require.NoError(t, err)

		inv := &inventory.Config{Options: map[string]string{
			// flag not set
		}}
		_, err = container.NewImageConnection(1, inv, &inventory.Asset{}, img, ref)
		require.NoError(t, err)
		require.Empty(t, inv.Options[container.OPTION_FILE_OCI])
	})

	t.Run("include oci sets oci tar file opt", func(t *testing.T) {
		err := cacheAlpine()
		require.NoError(t, err, "should create tar without error")

		ref, err := name.ParseReference(alpineImage, name.WeakValidation)
		require.NoError(t, err)

		img, err := tarball.ImageFromPath(alpineContainerPath, nil)
		require.NoError(t, err)

		inv := &inventory.Config{Options: map[string]string{
			container.INCLUDE_OCI_TAR_OPT_KEY: "true",
		}}
		_, err = container.NewImageConnection(1, inv, &inventory.Asset{}, img, ref)
		require.NoError(t, err)
		require.NotEmpty(t, inv.Options[container.OPTION_FILE_OCI])
	})
}

func TestImageConnections(t *testing.T) {
	var testConnections []dockerConnTest

	// create a connection to ta downloaded alpine image
	err := cacheAlpine()
	require.NoError(t, err, "should create tar without error")
	alpineConn, err := container.NewFromTar(0, &inventory.Config{
		Type: "tar",
		Options: map[string]string{
			tar.OPTION_FILE: alpineContainerPath,
		},
	}, &inventory.Asset{})
	require.NoError(t, err, "should create connection without error")
	testConnections = append(testConnections, dockerConnTest{
		name:     "alpine",
		conn:     alpineConn,
		testfile: "/etc/alpine-release",
	})

	// create a connection to a downloaded centos image
	err = cacheCentos()
	require.NoError(t, err, "should create tar without error")
	centosConn, err := container.NewFromTar(0, &inventory.Config{
		Type: "tar",
		Options: map[string]string{
			tar.OPTION_FILE: centosContainerPath,
		},
	}, &inventory.Asset{})
	require.NoError(t, err, "should create connection without error")
	testConnections = append(testConnections, dockerConnTest{
		name:     "centos",
		conn:     centosConn,
		testfile: "/etc/centos-release",
	})

	// create a connection to a remote alpine image
	alpineRemoteConn, err := container.NewRegistryImage(0, &inventory.Config{
		Type: "docker-image",
		Host: alpineImage,
	}, &inventory.Asset{})
	require.NoError(t, err, "should create remote connection without error")
	testConnections = append(testConnections, dockerConnTest{
		name:     "alpine",
		conn:     alpineRemoteConn,
		testfile: "/etc/alpine-release",
	})

	for _, test := range testConnections {
		t.Run("Test Connection for "+test.name, func(t *testing.T) {
			conn := test.conn
			require.NotNil(t, conn)
			t.Run("Test Run Command", func(t *testing.T) {
				cmd, err := conn.RunCommand("ls /")
				assert.Nil(t, err, "should execute without error")
				assert.Equal(t, -1, cmd.ExitStatus, "command should not be executed")
				stdoutContent, _ := io.ReadAll(cmd.Stdout)
				assert.Equal(t, "", string(stdoutContent), "output should be correct")
				stderrContent, _ := io.ReadAll(cmd.Stdout)
				assert.Equal(t, "", string(stderrContent), "output should be correct")
			})

			t.Run("Test Platform Identifier", func(t *testing.T) {
				platformId, err := conn.Identifier()
				require.NoError(t, err)
				assert.True(t, len(platformId) > 0)
			})

			t.Run("Test File Stat", func(t *testing.T) {
				f, err := conn.FileSystem().Open(test.testfile)
				assert.Nil(t, err)
				assert.Equal(t, nil, err, "should execute without error")

				p := f.Name()
				assert.Equal(t, test.testfile, p, "path should be correct")

				stat, err := f.Stat()
				assert.True(t, stat.Size() >= 6, "should read file size")
				assert.Equal(t, nil, err, "should execute without error")

				content, err := io.ReadAll(f)
				assert.Equal(t, nil, err, "should execute without error")
				assert.True(t, len(content) >= 6, "should read the full content")
			})

			t.Run("Test File Permissions", func(t *testing.T) {
				path := test.testfile
				details, err := conn.FileInfo(path)
				require.NoError(t, err)
				assert.Equal(t, int64(0), details.Uid)
				assert.Equal(t, int64(0), details.Gid)
				assert.True(t, details.Size >= 0)
				assert.Equal(t, false, details.Mode.IsDir())
				assert.Equal(t, true, details.Mode.IsRegular())
				assert.Equal(t, "-rw-r--r--", details.Mode.String())
				assert.True(t, details.Mode.UserReadable())
				assert.True(t, details.Mode.UserWriteable())
				assert.False(t, details.Mode.UserExecutable())
				assert.True(t, details.Mode.GroupReadable())
				assert.False(t, details.Mode.GroupWriteable())
				assert.False(t, details.Mode.GroupExecutable())
				assert.True(t, details.Mode.OtherReadable())
				assert.False(t, details.Mode.OtherWriteable())
				assert.False(t, details.Mode.OtherExecutable())
				assert.False(t, details.Mode.Suid())
				assert.False(t, details.Mode.Sgid())
				assert.False(t, details.Mode.Sticky())

				path = "/etc"
				details, err = conn.FileInfo(path)
				require.NoError(t, err)
				assert.Equal(t, int64(0), details.Uid)
				assert.Equal(t, int64(0), details.Gid)
				assert.True(t, details.Size >= 0)
				assert.True(t, details.Mode.IsDir())
				assert.False(t, details.Mode.IsRegular())
				assert.Equal(t, "drwxr-xr-x", details.Mode.String())
				assert.True(t, details.Mode.UserReadable())
				assert.True(t, details.Mode.UserWriteable())
				assert.True(t, details.Mode.UserExecutable())
				assert.True(t, details.Mode.GroupReadable())
				assert.False(t, details.Mode.GroupWriteable())
				assert.True(t, details.Mode.GroupExecutable())
				assert.True(t, details.Mode.OtherReadable())
				assert.False(t, details.Mode.OtherWriteable())
				assert.True(t, details.Mode.OtherExecutable())
				assert.False(t, details.Mode.Suid())
				assert.False(t, details.Mode.Sgid())
				assert.False(t, details.Mode.Sticky())
			})

			t.Run("Test Files Find", func(t *testing.T) {
				fs := conn.FileSystem()
				fSearch := fs.(*tar.FS)
				switch test.testfile {
				case "/etc/alpine-release":
					infos, err := fSearch.Find("/", regexp.MustCompile(`/etc/alpine-release`), "file", nil, nil)
					require.NoError(t, err)
					assert.Equal(t, 1, len(infos))
				case "/etc/centos-release":
					// the regex matches the whole path, as find -regex does
					infos, err := fSearch.Find("/", regexp.MustCompile(`/etc/centos-release`), "file", nil, nil)
					require.NoError(t, err)
					assert.Equal(t, []string{"/etc/centos-release"}, infos)
				}
			})
		})
	}
}

func TestTarSymlinkFile(t *testing.T) {
	err := cacheAlpine()
	require.NoError(t, err, "should create tar without error")

	c, err := container.NewFromTar(0, &inventory.Config{
		Type: "tar",
		Options: map[string]string{
			tar.OPTION_FILE: alpineContainerPath,
		},
	}, &inventory.Asset{})
	// require, not assert: c is dereferenced immediately below, so continuing
	// past a failure here segfaults the whole package rather than failing this
	// one test.
	require.NoError(t, err, "should create tar without error")

	f, err := c.FileSystem().Open("/bin/cat")
	assert.Nil(t, err)
	if assert.NotNil(t, f) {
		assert.Equal(t, nil, err, "should execute without error")

		p := f.Name()
		assert.Equal(t, "/bin/cat", p, "path should be correct")

		stat, err := f.Stat()
		assert.Equal(t, nil, err, "should stat without error")
		assert.True(t, stat.Size() > 0, "should read file size")

		content, err := io.ReadAll(f)
		assert.Equal(t, nil, err, "should execute without error")
		assert.True(t, len(content) > 0, "should read the full content")
	}
}

// deactivate test for now for speedier testing
// in contrast to alpine, the symlink on centos is pointing to a relative target and not an absolute one
func TestTarRelativeSymlinkFileCentos(t *testing.T) {
	err := cacheCentos()
	require.NoError(t, err, "should create tar without error")

	c, err := container.NewFromTar(0, &inventory.Config{
		Type: "tar",
		Options: map[string]string{
			tar.OPTION_FILE: centosContainerPath,
		},
	}, &inventory.Asset{})
	// require, not assert: c is dereferenced immediately below, so continuing
	// past a failure here segfaults the whole package rather than failing this
	// one test.
	require.NoError(t, err, "should create tar without error")

	f, err := c.FileSystem().Open("/etc/redhat-release")
	require.NoError(t, err)

	if assert.NotNil(t, f) {
		assert.Equal(t, nil, err, "should execute without error")

		p := f.Name()
		assert.Equal(t, "/etc/redhat-release", p, "path should be correct")

		stat, err := f.Stat()
		assert.Equal(t, nil, err, "should stat without error")
		assert.Equal(t, int64(37), stat.Size(), "should read file size")

		content, err := io.ReadAll(f)
		assert.Equal(t, nil, err, "should execute without error")
		assert.Equal(t, 37, len(content), "should read the full content")
	}
}
