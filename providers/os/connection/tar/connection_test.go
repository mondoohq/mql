// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar_test

import (
	archivetar "archive/tar"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/afero"
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

// FileInfo reports links the way the local connection does: a link to a file
// is a symlink with its target's size, a dangling link exists as a link, and a
// link loop is an error rather than a missing file.
func TestTarFileInfoSymlinkSemantics(t *testing.T) {
	c := usrMergedImage(t)

	fi, err := c.FileInfo("/etc/c3-links/tofile")
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode.FileMode&os.ModeSymlink, "isSymlink")
	assert.Equal(t, int64(6), fi.Size, "the target's size")

	fi, err = c.FileInfo("/bin")
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode.FileMode&os.ModeSymlink, "/bin is a symlink")
	assert.True(t, fi.Mode.FileMode&os.ModeDir != 0, "to a directory")

	fi, err = c.FileInfo("/etc/c3-links/broken")
	require.NoError(t, err, "a dangling link exists, as on a live system")
	assert.NotZero(t, fi.Mode.FileMode&os.ModeSymlink)

	_, err = c.FileInfo("/etc/c3-links/loop1")
	require.Error(t, err)
	assert.False(t, os.IsNotExist(err), "a loop is an error, not a missing file: %v", err)

	fi, err = c.FileInfo("/usr/bin/dash")
	require.NoError(t, err)
	assert.Zero(t, fi.Mode.FileMode&os.ModeSymlink)
	assert.Equal(t, int64(11), fi.Size)
}

// Reading a file seeks to the data offset recorded when the archive was
// loaded instead of scanning the archive for the entry. Entries whose header
// spans extra blocks (a PAX or GNU long name) must still read from the right
// offset, and a name the archive holds twice still reads as both copies.
func TestTarReadsEntriesAtTheirOffset(t *testing.T) {
	long := "usr/share/nodejs/" + strings.Repeat("very-long-package-name-", 8) + "/package.json"
	path := filepath.Join(t.TempDir(), "image.tar")
	f, err := os.Create(path)
	require.NoError(t, err)
	tw := archivetar.NewWriter(f)
	write := func(h *archivetar.Header, body string) {
		h.Size = int64(len(body))
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		require.NoError(t, tw.WriteHeader(h))
		_, err := tw.Write([]byte(body))
		require.NoError(t, err)
	}
	write(&archivetar.Header{Name: "etc/os-release", Typeflag: archivetar.TypeReg}, "ID=debian\n")
	write(&archivetar.Header{Name: long, Typeflag: archivetar.TypeReg, Format: archivetar.FormatPAX}, `{"name":"pax"}`)
	write(&archivetar.Header{Name: long + ".gnu", Typeflag: archivetar.TypeReg, Format: archivetar.FormatGNU}, `{"name":"gnu"}`)
	write(&archivetar.Header{Name: "etc/empty", Typeflag: archivetar.TypeReg}, "")
	write(&archivetar.Header{Name: "etc/twice", Typeflag: archivetar.TypeReg}, "first\n")
	write(&archivetar.Header{Name: "etc/twice", Typeflag: archivetar.TypeReg}, "second\n")
	require.NoError(t, tw.WriteHeader(&archivetar.Header{Name: "etc/hard", Typeflag: archivetar.TypeLink, Linkname: "etc/os-release"}))
	write(&archivetar.Header{Name: "etc/last", Typeflag: archivetar.TypeReg}, "last\n")
	require.NoError(t, tw.Close())
	require.NoError(t, f.Close())

	conn, err := tar.NewConnection(0, &inventory.Config{
		Type:    "tar",
		Options: map[string]string{tar.OPTION_FILE: path},
	}, &inventory.Asset{})
	require.NoError(t, err)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	for name, want := range map[string]string{
		"/etc/os-release":   "ID=debian\n",
		"/" + long:          `{"name":"pax"}`,
		"/" + long + ".gnu": `{"name":"gnu"}`,
		"/etc/empty":        "",
		"/etc/twice":        "first\nsecond\n",
		"/etc/hard":         "ID=debian\n",
		"/etc/last":         "last\n",
	} {
		got, err := afs.ReadFile(name)
		require.NoError(t, err, name)
		assert.Equal(t, want, string(got), name)
	}
}

// Reading files of a large image: each read used to scan the archive.
func BenchmarkTarReadFiles(b *testing.B) {
	path := filepath.Join(b.TempDir(), "image.tar")
	f, err := os.Create(path)
	require.NoError(b, err)
	tw := archivetar.NewWriter(f)
	body := strings.Repeat("x", 4096)
	for i := range 20000 {
		require.NoError(b, tw.WriteHeader(&archivetar.Header{Name: fmt.Sprintf("usr/share/f%d", i), Typeflag: archivetar.TypeReg, Mode: 0o644, Size: int64(len(body))}))
		_, err := tw.Write([]byte(body))
		require.NoError(b, err)
	}
	require.NoError(b, tw.Close())
	require.NoError(b, f.Close())
	conn, err := tar.NewConnection(0, &inventory.Config{Type: "tar", Options: map[string]string{tar.OPTION_FILE: path}}, &inventory.Asset{})
	require.NoError(b, err)
	afs := &afero.Afero{Fs: conn.FileSystem()}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range 100 {
			if _, err := afs.ReadFile(fmt.Sprintf("/usr/share/f%d", j*199)); err != nil {
				b.Fatal(err)
			}
		}
	}
}
