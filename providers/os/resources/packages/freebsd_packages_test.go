// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func freebsdPlatform() *inventory.Platform {
	return &inventory.Platform{Name: "freebsd", Arch: "amd64", Version: "14.5", Family: []string{"bsd", "unix", "os"}}
}

func freebsdByName(pkgs []Package) map[string]Package {
	m := make(map[string]Package, len(pkgs))
	for _, p := range pkgs {
		m[p.Name] = p
	}
	return m
}

// The five-column list older builds asked pkg for still parses: no install
// time, no license.
func TestParseFreeBSDPackages(t *testing.T) {
	f, err := os.Open("testdata/freebsd-package-info-streaming.txt")
	require.NoError(t, err)
	defer f.Close()

	m, err := ParseFreeBSDPackages(nil, f)
	require.Nil(t, err)
	assert.Equal(t, 32, len(m), "detected the right amount of packages")

	p := freebsdByName(m)["brotli"]
	assert.Equal(t, "1.1.0,1", p.Version)
	assert.Equal(t, "FreeBSD:14:amd64", p.Arch)
	assert.Equal(t, "Generic-purpose lossless compression algorithm", p.Description)
	assert.Equal(t, "archivers/brotli", p.Origin)
	assert.True(t, p.InstallDate.IsZero())
	assert.Empty(t, p.License)
}

// Captured with `pkg query '%n\t%v\t%c\t%q\t%o\t%t\t%l\t%L'` on FreeBSD
// 14.5-RELEASE (pkg 2.7.5).
func TestParseFreeBSDPackagesFull(t *testing.T) {
	f, err := os.Open("testdata/freebsd14-pkg-query.txt")
	require.NoError(t, err)
	defer f.Close()

	pkgs, err := ParseFreeBSDPackages(freebsdPlatform(), f)
	require.NoError(t, err)
	require.Len(t, pkgs, 8)
	m := freebsdByName(pkgs)

	jq := m["jq"]
	assert.Equal(t, "1.8.2", jq.Version)
	assert.Equal(t, "textproc/jq", jq.Origin)
	assert.Equal(t, "FreeBSD:14:amd64", jq.Arch)
	assert.Equal(t, "MIT", jq.License)
	assert.Equal(t, time.Date(2026, 9, 28, 3, 9, 33, 0, time.UTC), jq.InstallDate)
	assert.Equal(t, PkgFilesAsync, jq.FilesAvailable)
	assert.Equal(t, "pkg:generic/freebsd/jq@1.8.2?arch=amd64", jq.PUrl)

	// pkg version strings carry commas (PORTEPOCH) that the purl must escape.
	assert.Equal(t, "pkg:generic/freebsd/nginx@1.30.4%2C3?arch=amd64", m["nginx"].PUrl)

	// Dual licensed (%l "or") and multi licensed (%l "and").
	assert.Equal(t, "ART10 OR GPLv1+", m["perl5"].License)
	assert.Equal(t, "APACHE20 AND CUPS", m["cups"].License)
	assert.Equal(t, "AMS AND AREV AND BITSTREAM", m["dejavu"].License)

	// An architecture independent package names no arch in its purl.
	assert.Equal(t, "FreeBSD:14:*", m["dejavu"].Arch)
	assert.Equal(t, "pkg:generic/freebsd/dejavu@2.37_4", m["dejavu"].PUrl)

	// No license recorded reads empty, not a stray separator.
	assert.Empty(t, m["firstboot-pkgs"].License)
}

// Captured on FreeBSD 15.1-RELEASE installed with pkgbase: the base system
// is packages too, with a base/ origin.
func TestParseFreeBSDPackagesPkgbase(t *testing.T) {
	f, err := os.Open("testdata/freebsd15-pkgbase-query.txt")
	require.NoError(t, err)
	defer f.Close()

	pkgs, err := ParseFreeBSDPackages(freebsdPlatform(), f)
	require.NoError(t, err)
	m := freebsdByName(pkgs)

	rt := m["FreeBSD-runtime"]
	assert.Equal(t, "15.1p3", rt.Version)
	assert.Equal(t, "base/FreeBSD-runtime", rt.Origin)
	assert.Equal(t, "BSD2CLAUSE", rt.License)
	assert.Equal(t, time.Unix(1790564271, 0).UTC(), rt.InstallDate)
	assert.Equal(t, "pkg:generic/freebsd/FreeBSD-runtime@15.1p3?arch=amd64", rt.PUrl)

	// The comment is kept as pkg reports it, trailing space included.
	assert.Equal(t, "FreeBSD GENERIC Kernel ", m["FreeBSD-kernel-generic"].Description)
}

func TestParseFreeBSDInstallTime(t *testing.T) {
	assert.Equal(t, time.Unix(1790564973, 0).UTC(), parseFreeBSDInstallTime("1790564973"))
	assert.True(t, parseFreeBSDInstallTime("0").IsZero())
	assert.True(t, parseFreeBSDInstallTime("").IsZero())
	assert.True(t, parseFreeBSDInstallTime("-1").IsZero())
}

func TestFreeBSDLicense(t *testing.T) {
	assert.Equal(t, "", freebsdLicense("single", ""))
	assert.Equal(t, "MIT", freebsdLicense("single", "MIT"))
	assert.Equal(t, "ART10 OR GPLv1+", freebsdLicense("or", "ART10, GPLv1+"))
	assert.Equal(t, "GPLv3 AND LGPL3", freebsdLicense("and", "GPLv3, LGPL3"))
	// Several licenses with no known logic keep pkg's own list.
	assert.Equal(t, "A, B", freebsdLicense("", "A, B"))
}

func TestFreeBSDAbiArch(t *testing.T) {
	assert.Equal(t, "amd64", freebsdAbiArch("FreeBSD:14:amd64"))
	assert.Equal(t, "aarch64", freebsdAbiArch("FreeBSD:15:aarch64"))
	assert.Equal(t, "", freebsdAbiArch("FreeBSD:14:*"))
	assert.Equal(t, "", freebsdAbiArch(""))
}

// Captured with `pkg version -vRL=` as root on FreeBSD 15.1-RELEASE, which
// prints the catalogue refresh on stdout before the comparison.
func TestParseFreeBSDUpdates(t *testing.T) {
	f, err := os.Open("testdata/freebsd15-pkg-version.txt")
	require.NoError(t, err)
	defer f.Close()

	arches := map[string]string{
		"ca_root_nss":        "FreeBSD:15:*",
		"amazon-ssm-agent":   "FreeBSD:15:amd64",
		"aws-ec2-imdsv2-get": "FreeBSD:15:amd64",
	}
	updates, err := ParseFreeBSDUpdates(f, arches)
	require.NoError(t, err)
	require.Len(t, updates, 3)

	assert.Equal(t, PackageUpdate{
		Name:      "aws-ec2-imdsv2-get",
		Version:   "1.0.7_11",
		Available: "1.0.7_13",
		Arch:      "FreeBSD:15:amd64",
	}, updates["aws-ec2-imdsv2-get"])
	assert.Equal(t, "3.130", updates["ca_root_nss"].Available)
	assert.Equal(t, "FreeBSD:15:*", updates["ca_root_nss"].Arch)
}

// Hand-written in the format of pkg version -v for the states the hosts did not
// show: up to date, orphaned and newer than the catalogue.
func TestParseFreeBSDUpdatesSkipsNonUpdates(t *testing.T) {
	in := strings.Join([]string{
		"pkg-2.7.5                          =   up-to-date with remote",
		"firstboot-pkgs-1.7                 ?   orphaned: sysutils/firstboot-pkgs",
		"curl-8.17.0                        >   succeeds remote (remote has 8.16.0)",
		"libssh2-1.11.1,3                   <   needs updating (remote has 1.11.1_1,3)",
	}, "\n")
	updates, err := ParseFreeBSDUpdates(strings.NewReader(in), nil)
	require.NoError(t, err)
	require.Len(t, updates, 1)
	assert.Equal(t, "1.11.1,3", updates["libssh2"].Version)
	assert.Equal(t, "1.11.1_1,3", updates["libssh2"].Available)
}

// Captured with `pkg query %Fp jq` on FreeBSD 14.5-RELEASE.
func TestParseFreeBSDFileList(t *testing.T) {
	f, err := os.Open("testdata/freebsd14-pkg-files-jq.txt")
	require.NoError(t, err)
	defer f.Close()

	files, err := ParseFreeBSDFileList(f)
	require.NoError(t, err)
	require.Len(t, files, 16)
	assert.Equal(t, "/usr/local/bin/jq", files[0].Path)
	assert.Contains(t, files, FileRecord{Path: "/usr/local/include/jv.h"})
}
