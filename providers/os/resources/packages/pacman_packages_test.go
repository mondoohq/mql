// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages_test

import (
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/resources/packages"
)

func TestPacmanParser(t *testing.T) {
	pf := &inventory.Platform{
		Name:    "arch",
		Version: "",
		Arch:    "x86_64",
		Family:  []string{"arch", "linux", "unix", "os"},
		Labels: map[string]string{
			"distro-id": "arch",
		},
	}

	pkgList := `qpdfview 0.4.17beta1-4.1
usbmuxd 1.1.0+28+g46bdf3e-1
vertex-maia-themes 20171114-1
xfce4-power-manager 1.6.0.41.g9daecb5-1
xfce4-pulseaudio-plugin 0.3.2.r13.g553691a-1
zita-alsa-pcmi 0.2.0-3
zlib 1:1.2.11-2
zziplib 0.13.67-1`

	m := packages.ParsePacmanPackages(pf, strings.NewReader(pkgList))

	assert.Equal(t, 8, len(m), "detected the right amount of packages")
	p := packages.Package{
		Name:           "qpdfview",
		Version:        "0.4.17beta1-4.1",
		PUrl:           "pkg:alpm/arch/qpdfview@0.4.17beta1-4.1?arch=x86_64&distro=arch",
		Format:         packages.PacmanPkgFormat,
		FilesAvailable: packages.PkgFilesAsync,
	}
	assert.Contains(t, m, p, "pkg detected")

	p = packages.Package{
		Name:           "vertex-maia-themes",
		Version:        "20171114-1",
		PUrl:           "pkg:alpm/arch/vertex-maia-themes@20171114-1?arch=x86_64&distro=arch",
		Format:         packages.PacmanPkgFormat,
		FilesAvailable: packages.PkgFilesAsync,
	}
	assert.Contains(t, m, p, "pkg detected")

	p = packages.Package{
		Name:           "xfce4-pulseaudio-plugin",
		Version:        "0.3.2.r13.g553691a-1",
		PUrl:           "pkg:alpm/arch/xfce4-pulseaudio-plugin@0.3.2.r13.g553691a-1?arch=x86_64&distro=arch",
		Format:         packages.PacmanPkgFormat,
		FilesAvailable: packages.PkgFilesAsync,
	}
	assert.Contains(t, m, p, "pkg detected")
}

func TestPacmanWithWarningsParser(t *testing.T) {
	pf := &inventory.Platform{
		Name:    "arch",
		Version: "",
		Arch:    "x86_64",
		Family:  []string{"arch", "linux", "unix", "os"},
		Labels: map[string]string{
			"distro-id": "arch",
		},
	}

	pkgList := `warning: database file for 'core' does not exist (use '-Sy' to download)
warning: database file for 'extra' does not exist (use '-Sy' to download)
warning: database file for 'community' does not exist (use '-Sy' to download)
acl 2.2.53-2
archlinux-keyring 20200108-1
argon2 20190702-2`

	m := packages.ParsePacmanPackages(pf, strings.NewReader(pkgList))

	assert.Equal(t, 3, len(m), "detected the right amount of packages")
	p := packages.Package{
		Name:           "acl",
		Version:        "2.2.53-2",
		PUrl:           "pkg:alpm/arch/acl@2.2.53-2?arch=x86_64&distro=arch",
		Format:         packages.PacmanPkgFormat,
		FilesAvailable: packages.PkgFilesAsync,
	}
	assert.Contains(t, m, p, "pkg detected")
}

func TestParsePacmanDB(t *testing.T) {
	pf := &inventory.Platform{
		Name:    "arch",
		Version: "",
		Arch:    "x86_64",
		Family:  []string{"arch", "linux", "unix", "os"},
		Labels: map[string]string{
			"distro-id": "arch",
		},
	}

	afs := &afero.Afero{Fs: afero.NewOsFs()}
	pkgs, err := packages.ParsePacmanDB(pf, afs, "./testdata/pacman")
	require.NoError(t, err)
	assert.Equal(t, 3, len(pkgs))

	var zlib *packages.Package
	for i := range pkgs {
		if pkgs[i].Name == "zlib" {
			zlib = &pkgs[i]
			break
		}
	}
	require.NotNil(t, zlib)
	assert.Equal(t, "1:1.2.13-3", zlib.Version)
	assert.Equal(t, "x86_64", zlib.Arch)
	assert.Contains(t, zlib.Description, "Compression library")
	assert.Equal(t, "pacman", zlib.Format)
	assert.Contains(t, zlib.PUrl, "pkg:alpm/arch/zlib")
	assert.Equal(t, "custom:Zlib", zlib.License)
	assert.Equal(t, packages.PkgFilesAsync, zlib.FilesAvailable)

	var openssl *packages.Package
	for i := range pkgs {
		if pkgs[i].Name == "openssl" {
			openssl = &pkgs[i]
			break
		}
	}
	require.NotNil(t, openssl)
	assert.Equal(t, "3.2.1-1", openssl.Version)
	assert.Contains(t, openssl.Description, "Open Source toolkit")
	assert.Equal(t, "Apache-2.0", openssl.License)
}

// pacmanDescStreamFixture is two desc records exactly as
// `find /var/lib/pacman/local -maxdepth 2 -name desc -exec cat {} +` emits
// them, taken from an archlinuxarm container. Note the blank lines *inside*
// each record: they are why %NAME%, not a blank line, separates records.
const pacmanDescStreamFixture = `%NAME%
bash

%VERSION%
5.3.15-1

%BASE%
bash

%DESC%
The GNU Bourne Again shell

%URL%
https://www.gnu.org/software/bash/bash.html

%ARCH%
aarch64

%BUILDDATE%
1781156286

%LICENSE%
GPL-3.0-or-later

%VALIDATION%
pgp

%NAME%
archlinux-keyring

%VERSION%
20260909-1

%DESC%
Arch Linux PGP keyring

%ARCH%
any

%LICENSE%
GPL-3.0-or-later

%XDATA%
pkgtype=pkg

`

func TestParsePacmanDescStream(t *testing.T) {
	pf := &inventory.Platform{
		Name:    "arch",
		Version: "rolling",
		Arch:    "aarch64",
		Family:  []string{"arch", "linux", "unix", "os"},
		Labels:  map[string]string{"distro-id": "arch"},
	}

	pkgs := packages.ParsePacmanDescStream(pf, strings.NewReader(pacmanDescStreamFixture))
	require.Len(t, pkgs, 2)

	// The fields `pacman -Q` cannot report are the point of this path:
	// reverting List() to the CLI leaves arch, description and license empty.
	assert.Equal(t, "bash", pkgs[0].Name)
	assert.Equal(t, "5.3.15-1", pkgs[0].Version)
	assert.Equal(t, "aarch64", pkgs[0].Arch)
	assert.Equal(t, "The GNU Bourne Again shell", pkgs[0].Description)
	assert.Equal(t, "GPL-3.0-or-later", pkgs[0].License)
	assert.Equal(t, packages.PacmanPkgFormat, pkgs[0].Format)

	// "any" is pacman's noarch; it must survive as written rather than being
	// replaced by the platform architecture.
	assert.Equal(t, "archlinux-keyring", pkgs[1].Name)
	assert.Equal(t, "20260909-1", pkgs[1].Version)
	assert.Equal(t, "any", pkgs[1].Arch)
	assert.Equal(t, "Arch Linux PGP keyring", pkgs[1].Description)
}

func TestParsePacmanDescStreamEdgeCases(t *testing.T) {
	pf := &inventory.Platform{Name: "arch", Arch: "aarch64"}

	t.Run("empty input yields no packages", func(t *testing.T) {
		assert.Empty(t, packages.ParsePacmanDescStream(pf, strings.NewReader("")))
	})

	t.Run("record without a name is not a package", func(t *testing.T) {
		assert.Empty(t, packages.ParsePacmanDescStream(pf, strings.NewReader("%VERSION%\n1.0-1\n\n")))
	})

	t.Run("final record with no trailing blank line is kept", func(t *testing.T) {
		pkgs := packages.ParsePacmanDescStream(pf, strings.NewReader("%NAME%\nzlib\n\n%VERSION%\n1.3.1-2"))
		require.Len(t, pkgs, 1)
		assert.Equal(t, "zlib", pkgs[0].Name)
		assert.Equal(t, "1.3.1-2", pkgs[0].Version)
	})

	t.Run("a value that looks like a header does not split the record", func(t *testing.T) {
		// %DESC% values are free text; only a bare %NAME% line opens a record.
		pkgs := packages.ParsePacmanDescStream(pf, strings.NewReader(
			"%NAME%\nfoo\n\n%DESC%\nprints %VERSION% and friends\n\n%VERSION%\n2.0-1\n\n"))
		require.Len(t, pkgs, 1)
		assert.Equal(t, "foo", pkgs[0].Name)
		assert.Equal(t, "2.0-1", pkgs[0].Version)
	})
}

// TestPacmanEpoch pins that a pacman package carrying an epoch reports it on
// its own field, keeps the epoch inside version the way rpm and dpkg do, and
// carries the epoch qualifier on its purl -- through both readers.
//
// The four packages below are the epoch-bearing ones on a stock
// menci/archlinuxarm container: iptables, lz4, nftables and zlib.
func TestPacmanEpoch(t *testing.T) {
	pf := &inventory.Platform{
		Name:    "arch",
		Version: "rolling",
		Arch:    "aarch64",
		Family:  []string{"arch", "linux", "unix", "os"},
		Labels:  map[string]string{"distro-id": "arch"},
	}

	t.Run("pacman -Q reader", func(t *testing.T) {
		pkgs := packages.ParsePacmanPackages(pf, strings.NewReader(
			"iptables 1:1.8.13-1\nbash 5.3.15-1\n"))
		require.Len(t, pkgs, 2)

		assert.Equal(t, "iptables", pkgs[0].Name)
		assert.Equal(t, "1", pkgs[0].Epoch)
		assert.Equal(t, "1:1.8.13-1", pkgs[0].Version, "version keeps the epoch")
		assert.Contains(t, pkgs[0].PUrl, "epoch=1")

		assert.Equal(t, "bash", pkgs[1].Name)
		assert.Empty(t, pkgs[1].Epoch)
		assert.NotContains(t, pkgs[1].PUrl, "epoch=")
	})

	t.Run("local database reader", func(t *testing.T) {
		pkgs := packages.ParsePacmanDescStream(pf, strings.NewReader(
			"%NAME%\nlz4\n\n%VERSION%\n1:1.10.0-2\n\n%ARCH%\naarch64\n\n"+
				"%NAME%\nbash\n\n%VERSION%\n5.3.15-1\n\n%ARCH%\naarch64\n\n"))
		require.Len(t, pkgs, 2)

		assert.Equal(t, "lz4", pkgs[0].Name)
		assert.Equal(t, "1", pkgs[0].Epoch)
		assert.Equal(t, "1:1.10.0-2", pkgs[0].Version)
		assert.Contains(t, pkgs[0].PUrl, "epoch=1")

		assert.Empty(t, pkgs[1].Epoch)
		assert.NotContains(t, pkgs[1].PUrl, "epoch=")
	})
}
