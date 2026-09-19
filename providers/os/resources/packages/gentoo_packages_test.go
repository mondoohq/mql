// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGentooPackages(t *testing.T) {
	f, err := os.Open("testdata/gentoo_qlist.txt")
	require.NoError(t, err)
	defer f.Close()

	m, err := ParseGentooPackages(nil, f)
	require.NoError(t, err)
	assert.Equal(t, 13, len(m), "detected the right amount of packages")

	p := m[10] // net-misc/curl:8.4.0
	assert.Equal(t, "net-misc/curl", p.Name)
	assert.Equal(t, "8.4.0", p.Version)
	assert.Equal(t, "gentoo", p.Format)
	assert.Contains(t, p.PUrl, "pkg:ebuild/net-misc/curl@8.4.0")
}

func TestParseGentooPackagesRevision(t *testing.T) {
	f, err := os.Open("testdata/gentoo_qlist.txt")
	require.NoError(t, err)
	defer f.Close()

	m, err := ParseGentooPackages(nil, f)
	require.NoError(t, err)

	// net-misc/dhcpcd:10.0.5-r1
	p := m[11]
	assert.Equal(t, "net-misc/dhcpcd", p.Name)
	assert.Equal(t, "10.0.5-r1", p.Version)
	assert.Contains(t, p.PUrl, "pkg:ebuild/net-misc/dhcpcd@10.0.5-r1")
}

func TestParsePortageDB(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewOsFs()}
	pkgs, err := ParsePortageDB(nil, afs, "testdata/portage")
	require.NoError(t, err)
	require.Len(t, pkgs, 3)

	// Sort order depends on OS readdir — find by name
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	curl := byName["net-misc/curl"]
	assert.Equal(t, "8.4.0", curl.Version)
	assert.Equal(t, "gentoo", curl.Format)
	assert.Contains(t, curl.PUrl, "pkg:ebuild/net-misc/curl@8.4.0")
	assert.Contains(t, curl.Description, "Client and Server")

	dhcpcd := byName["net-misc/dhcpcd"]
	assert.Equal(t, "10.0.5-r1", dhcpcd.Version)
	assert.Contains(t, dhcpcd.Description, "DHCP client")

	audio := byName["acct-group/audio"]
	assert.Equal(t, "0-r2", audio.Version)
}

func TestSplitPortageDirName(t *testing.T) {
	tests := []struct {
		input   string
		name    string
		version string
	}{
		{"curl-8.4.0", "curl", "8.4.0"},
		{"dhcpcd-10.0.5-r1", "dhcpcd", "10.0.5-r1"},
		{"audio-0-r2", "audio", "0-r2"},
		{"libmnl-1.0.5", "libmnl", "1.0.5"},
		{"nghttp2-1.57.0", "nghttp2", "1.57.0"},
		{"iputils-20221126-r1", "iputils", "20221126-r1"},
	}
	for _, tt := range tests {
		name, version := splitPortageDirName(tt.input)
		assert.Equal(t, tt.name, name, "splitPortageDirName(%q) name", tt.input)
		assert.Equal(t, tt.version, version, "splitPortageDirName(%q) version", tt.input)
	}
}

func TestSplitCategoryName(t *testing.T) {
	cat, name := splitCategoryName("net-misc/curl")
	assert.Equal(t, "net-misc", cat)
	assert.Equal(t, "curl", name)

	cat, name = splitCategoryName("acct-group/audio")
	assert.Equal(t, "acct-group", cat)
	assert.Equal(t, "audio", name)

	cat, name = splitCategoryName("nocat")
	assert.Equal(t, "", cat)
	assert.Equal(t, "nocat", name)
}

// The two command outputs below are verbatim from a gentoo/stage3:arm64
// container.
const portageDirsFixture = `/var/db/pkg/net-misc/netifrc-0.7.3
/var/db/pkg/net-misc/curl-7.79.1
/var/db/pkg/net-misc/rsync-3.2.3-r5
/var/db/pkg/acct-group/audio-0-r1
`

const portageMetaFixture = `/var/db/pkg/net-misc/netifrc-0.7.3/DESCRIPTION:Gentoo Network Interface Management Scripts
/var/db/pkg/net-misc/netifrc-0.7.3/LICENSE:BSD-2
/var/db/pkg/net-misc/curl-7.79.1/DESCRIPTION:A Client that groks URLs
/var/db/pkg/net-misc/curl-7.79.1/LICENSE:curl
/var/db/pkg/net-misc/rsync-3.2.3-r5/DESCRIPTION:File transfer program to keep remote files into sync
/var/db/pkg/net-misc/rsync-3.2.3-r5/LICENSE:GPL-3
`

func TestParsePortageDBDirs(t *testing.T) {
	pkgs, err := ParsePortageDBDirs(nil, strings.NewReader(portageDirsFixture))
	require.NoError(t, err)
	require.Len(t, pkgs, 4)

	assert.Equal(t, "net-misc/netifrc", pkgs[0].Name)
	assert.Equal(t, "0.7.3", pkgs[0].Version)
	assert.Equal(t, GentooPkgFormat, pkgs[0].Format)

	// a -rN revision belongs to the version, not the name
	assert.Equal(t, "net-misc/rsync", pkgs[2].Name)
	assert.Equal(t, "3.2.3-r5", pkgs[2].Version)

	// a package whose version is bare "0-r1"
	assert.Equal(t, "acct-group/audio", pkgs[3].Name)
	assert.Equal(t, "0-r1", pkgs[3].Version)
}

func TestParsePortageMetaAndApply(t *testing.T) {
	pkgs, err := ParsePortageDBDirs(nil, strings.NewReader(portageDirsFixture))
	require.NoError(t, err)

	// Before: qlist and the directory listing know nothing but name/version.
	assert.Empty(t, pkgs[1].Description)
	assert.Empty(t, pkgs[1].License)

	applyPortageMeta(pkgs, ParsePortageMeta(strings.NewReader(portageMetaFixture)))

	assert.Equal(t, "A Client that groks URLs", pkgs[1].Description)
	assert.Equal(t, "curl", pkgs[1].License)
	assert.Equal(t, "Gentoo Network Interface Management Scripts", pkgs[0].Description)
	assert.Equal(t, "BSD-2", pkgs[0].License)
	assert.Equal(t, "GPL-3", pkgs[2].License)

	// acct-group/audio has neither file on a real system; it must survive the
	// merge with empty metadata rather than be dropped or take a neighbour's.
	assert.Equal(t, "acct-group/audio", pkgs[3].Name)
	assert.Empty(t, pkgs[3].Description)
	assert.Empty(t, pkgs[3].License)
}

func TestParsePortageMetaEdgeCases(t *testing.T) {
	t.Run("a value containing a colon is kept whole", func(t *testing.T) {
		meta := ParsePortageMeta(strings.NewReader(
			"/var/db/pkg/app-misc/foo-1.0/DESCRIPTION:See http://example.com: the docs\n"))
		assert.Equal(t, "See http://example.com: the docs",
			meta["/var/db/pkg/app-misc/foo-1.0"]["DESCRIPTION"])
	})

	t.Run("an empty value is kept", func(t *testing.T) {
		meta := ParsePortageMeta(strings.NewReader("/var/db/pkg/app-misc/foo-1.0/LICENSE:\n"))
		assert.Equal(t, "", meta["/var/db/pkg/app-misc/foo-1.0"]["LICENSE"])
	})

	t.Run("a line with no colon is skipped", func(t *testing.T) {
		assert.Empty(t, ParsePortageMeta(strings.NewReader("grep: no such file\n\n")))
	})
}

func TestPackageFromPortageDir(t *testing.T) {
	assert.Nil(t, packageFromPortageDir(nil, ""), "empty path")
	assert.Nil(t, packageFromPortageDir(nil, "/var/db/pkg/net-misc"), "no version")
	assert.Nil(t, packageFromPortageDir(nil, "/var/db/pkg/net-misc/curl"), "no version")

	p := packageFromPortageDir(nil, "/var/db/pkg/net-misc/curl-7.79.1/")
	require.NotNil(t, p, "a trailing slash must not defeat the split")
	assert.Equal(t, "net-misc/curl", p.Name)
	assert.Equal(t, "7.79.1", p.Version)
}
