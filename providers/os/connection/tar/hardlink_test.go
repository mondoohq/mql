// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar_test

import (
	archivetar "archive/tar"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

const osReleaseBody = "NAME=\"Fedora Linux\"\nID=fedora\nVERSION_ID=42\n"

// writeOSTreeStyleTar builds the layout every OSTree/bootc image ships: the
// real content lives in the ostree object store, the visible path is a tar
// hardlink to it, and /etc/os-release is a symlink to that hardlink.
//
//	sysroot/ostree/repo/objects/ab/cdef.file   regular file, holds the bytes
//	usr/lib/os-release                         hardlink -> the object above
//	etc/os-release                             symlink  -> ../usr/lib/os-release
func writeOSTreeStyleTar(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ostree.tar")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	tw := archivetar.NewWriter(f)
	object := "sysroot/ostree/repo/objects/ab/cdef.file"

	require.NoError(t, tw.WriteHeader(&archivetar.Header{
		Name:     object,
		Typeflag: archivetar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(osReleaseBody)),
	}))
	_, err = tw.Write([]byte(osReleaseBody))
	require.NoError(t, err)

	// a hardlink entry carries no payload of its own: size is 0 and the real
	// path is in Linkname
	require.NoError(t, tw.WriteHeader(&archivetar.Header{
		Name:     "usr/lib/os-release",
		Typeflag: archivetar.TypeLink,
		Linkname: object,
		Mode:     0o644,
	}))

	require.NoError(t, tw.WriteHeader(&archivetar.Header{
		Name:     "etc/os-release",
		Typeflag: archivetar.TypeSymlink,
		Linkname: "../usr/lib/os-release",
		Mode:     0o777,
	}))

	require.NoError(t, tw.Close())
	return path
}

func ostreeConn(t *testing.T, path string) *tar.Connection {
	t.Helper()
	c, err := tar.NewConnection(0, &inventory.Config{
		Type:    "tar",
		Options: map[string]string{tar.OPTION_FILE: path},
	}, &inventory.Asset{})
	require.NoError(t, err)
	return c
}

// A hardlinked file reads as empty: the header the entry carries has Size 0,
// so extracting by that entry's own name yields no bytes. Every OSTree and
// bootc image (Fedora CoreOS, Fedora bootc, the uBlue images) stores
// /usr/lib/os-release this way, which left the whole platform undetected and
// reported container images as "scratch".
func TestTarHardlinkContent(t *testing.T) {
	c := ostreeConn(t, writeOSTreeStyleTar(t))

	f, err := c.FileSystem().Open("/usr/lib/os-release")
	require.NoError(t, err)
	defer f.Close()

	content, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, osReleaseBody, string(content), "hardlink must read the content of its target")
}

func TestTarHardlinkStatSize(t *testing.T) {
	c := ostreeConn(t, writeOSTreeStyleTar(t))

	stat, err := c.FileSystem().Stat("/usr/lib/os-release")
	require.NoError(t, err)
	assert.Equal(t, int64(len(osReleaseBody)), stat.Size(), "hardlink must report its target's size")
}

// The path detection actually opens: a symlink whose target is a hardlink.
func TestTarSymlinkToHardlinkContent(t *testing.T) {
	c := ostreeConn(t, writeOSTreeStyleTar(t))

	f, err := c.FileSystem().Open("/etc/os-release")
	require.NoError(t, err)
	defer f.Close()

	content, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, osReleaseBody, string(content), "symlink to a hardlink must read through both")
}

const fedoraReleaseBody = "Fedora release 44 (Fedora CoreOS)\n"

// A hardlink whose target is a symlink with a relative link, which is what
// /etc/redhat-release is on an OSTree image:
//
//	etc/fedora-release                    the content
//	sysroot/ostree/repo/objects/e8/..file symlink -> fedora-release
//	etc/redhat-release                    hardlink -> the object above
//
// A hardlink names an inode, not a path, so "fedora-release" has to resolve
// against /etc, the directory the file is being reached through, and not
// against the object store the symlink physically lives in. Resolving it the
// other way looks for /sysroot/ostree/repo/objects/e8/fedora-release, which
// does not exist, and the redhat family then declines the whole subtree.
func TestTarHardlinkToRelativeSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ostree-release.tar")
	f, err := os.Create(path)
	require.NoError(t, err)

	tw := archivetar.NewWriter(f)
	object := "sysroot/ostree/repo/objects/e8/1400dd.file"

	require.NoError(t, tw.WriteHeader(&archivetar.Header{
		Name:     "etc/fedora-release",
		Typeflag: archivetar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(fedoraReleaseBody)),
	}))
	_, err = tw.Write([]byte(fedoraReleaseBody))
	require.NoError(t, err)

	require.NoError(t, tw.WriteHeader(&archivetar.Header{
		Name:     object,
		Typeflag: archivetar.TypeSymlink,
		Linkname: "fedora-release",
		Mode:     0o777,
	}))
	require.NoError(t, tw.WriteHeader(&archivetar.Header{
		Name:     "etc/redhat-release",
		Typeflag: archivetar.TypeLink,
		Linkname: object,
		Mode:     0o644,
	}))
	require.NoError(t, tw.Close())
	require.NoError(t, f.Close())

	c := ostreeConn(t, path)

	rf, err := c.FileSystem().Open("/etc/redhat-release")
	require.NoError(t, err)
	defer rf.Close()

	content, err := io.ReadAll(rf)
	require.NoError(t, err)
	assert.Equal(t, fedoraReleaseBody, string(content))
}

// A link chain that never terminates must fail rather than hang the scan.
func TestTarLinkCycleTerminates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cycle.tar")
	f, err := os.Create(path)
	require.NoError(t, err)

	tw := archivetar.NewWriter(f)
	require.NoError(t, tw.WriteHeader(&archivetar.Header{
		Name: "a", Typeflag: archivetar.TypeSymlink, Linkname: "/b", Mode: 0o777,
	}))
	require.NoError(t, tw.WriteHeader(&archivetar.Header{
		Name: "b", Typeflag: archivetar.TypeSymlink, Linkname: "/a", Mode: 0o777,
	}))
	require.NoError(t, tw.Close())
	require.NoError(t, f.Close())

	c := ostreeConn(t, path)

	_, err = c.FileSystem().Open("/a")
	assert.Error(t, err, "a symlink cycle must not resolve")
}
