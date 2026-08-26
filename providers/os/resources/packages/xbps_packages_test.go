// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/packages"
)

func voidPlatform() *inventory.Platform {
	return &inventory.Platform{
		Name:    "void",
		Arch:    "x86_64",
		Family:  []string{"linux", "unix", "os"},
		Runtime: "docker-image",
	}
}

// The fixture is the real database from voidlinux/voidlinux, trimmed to four
// packages plus the _XBPS_ALTERNATIVES_ bookkeeping entry.
func TestParseXbpsPkgdb(t *testing.T) {
	f, err := os.Open("./testdata/xbps_pkgdb.plist")
	require.NoError(t, err)
	defer f.Close()

	pkgs, err := packages.ParseXbpsPkgdb(voidPlatform(), f)
	require.NoError(t, err)

	// _XBPS_ALTERNATIVES_ sits at the top level alongside the packages and is
	// a dict like they are. Counting it as a package would report a package
	// with no name and no version.
	require.Len(t, pkgs, 4, "the alternatives entry must not be counted as a package")
	for _, p := range pkgs {
		assert.NotEqual(t, "_XBPS_ALTERNATIVES_", p.Name)
	}

	byName := map[string]packages.Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	// A name with no hyphen, the simple case.
	acl := byName["acl"]
	assert.Equal(t, "2.3.1_1", acl.Version)
	assert.Equal(t, "x86_64", acl.Arch)
	assert.Equal(t, "Access Control List filesystem support", acl.Description)
	assert.Equal(t, "LGPL-2.1-or-later", acl.License)
	assert.Equal(t, "installed", acl.Status)
	assert.Equal(t, "xbps", acl.Format)
	assert.Equal(t, "2021-07-25T10:42:00Z", acl.InstallDate.UTC().Format("2006-01-02T15:04:05Z"))

	// xbps names contain hyphens, so the version cannot be found by splitting
	// on one. These are the cases that catch a split-based implementation.
	assert.Equal(t, "0.142_11", byName["base-files"].Version, "a hyphenated name must not be cut short")
	assert.Equal(t, "20210119+3.68_1", byName["ca-certificates"].Version, "a version containing + must survive")
	assert.Equal(t, "1.1.1k_1", byName["libcrypto1.1"].Version, "a name ending in digits and dots must not be eaten")
}

// A map has no order, so an unsorted implementation returns the packages in a
// different order on every scan of the same host.
func TestParseXbpsPkgdbIsStable(t *testing.T) {
	var first []string
	for i := 0; i < 5; i++ {
		f, err := os.Open("./testdata/xbps_pkgdb.plist")
		require.NoError(t, err)

		pkgs, err := packages.ParseXbpsPkgdb(voidPlatform(), f)
		require.NoError(t, err)
		f.Close()

		names := make([]string, 0, len(pkgs))
		for _, p := range pkgs {
			names = append(names, p.Name)
		}
		if first == nil {
			first = names
			continue
		}
		assert.Equal(t, first, names, "the package order must not change between scans")
	}
}

func TestParseXbpsPkgdbRejectsGarbage(t *testing.T) {
	_, err := packages.ParseXbpsPkgdb(voidPlatform(), strings.NewReader("not a plist"))
	assert.Error(t, err, "an unreadable database must be reported, not read as zero packages")
}

func TestParseXbpsFileList(t *testing.T) {
	f, err := os.Open("./testdata/xbps_acl_files.plist")
	require.NoError(t, err)
	defer f.Close()

	records, err := packages.ParseXbpsFileList(f)
	require.NoError(t, err)

	paths := make([]string, 0, len(records))
	for _, r := range records {
		paths = append(paths, r.Path)
	}

	// dirs, files and links are three separate arrays in the plist; all three
	// belong to the package.
	assert.Contains(t, paths, "/usr", "dirs must be included")
	assert.Contains(t, paths, "/usr/lib/libacl.so.1.1.2301", "files must be included")
	assert.NotEmpty(t, records)
}

func TestParseXbpsUpdates(t *testing.T) {
	// The shape xbps-install -Sun prints: pkgver, action, arch, repo, sizes.
	out := strings.Join([]string{
		"acl-2.3.2_1 update x86_64 https://repo-default.voidlinux.org/current 16502 38904",
		"base-files-0.143_1 update x86_64 https://repo-default.voidlinux.org/current 20000 40000",
		"ca-certificates-20230311_1 update noarch https://repo-default.voidlinux.org/current 1 2",
		"",
	}, "\n")

	updates, err := packages.ParseXbpsUpdates(strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, updates, 3)

	assert.Equal(t, "2.3.2_1", updates["acl"].Available)
	// again the hyphenated-name case, on the command path this time
	assert.Equal(t, "0.143_1", updates["base-files"].Available)
	assert.Equal(t, "20230311_1", updates["ca-certificates"].Available)
}

// An underscore is the revision separator, so a name containing one looks
// ambiguous. It is not: the search runs from the right, so the last "_" is
// still the revision and the name survives whole.
func TestParseXbpsUpdatesNameContainingUnderscore(t *testing.T) {
	out := strings.Join([]string{
		"my_pkg-1.0_1 update x86_64 https://repo-default.voidlinux.org/current 1 2",
		"pkg-my_name-2.5_3 update x86_64 https://repo-default.voidlinux.org/current 1 2",
		"",
	}, "\n")

	updates, err := packages.ParseXbpsUpdates(strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, updates, 2)

	assert.Equal(t, "1.0_1", updates["my_pkg"].Available)
	assert.Equal(t, "2.5_3", updates["pkg-my_name"].Available)
}

func TestParseXbpsUpdatesEmpty(t *testing.T) {
	updates, err := packages.ParseXbpsUpdates(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, updates)
}

// Void detection shipped in #10444 as detection-only, because nothing here
// claimed it: its family is [linux unix os], which matched no case in the
// resolver, so packages errored on a host whose database held 56 of them.
func TestResolveSystemPkgManagersVoid(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "void",
			Family: []string{"linux", "unix", "os"},
		},
	}, mock.WithPath("./testdata/packages_void.toml"))
	require.NoError(t, err)

	pms, err := packages.ResolveSystemPkgManagers(conn)
	require.NoError(t, err, "Void has an xbps database, so a manager must resolve")
	require.Len(t, pms, 1)
	assert.Equal(t, "xbps Package Manager", pms[0].Name())
}
