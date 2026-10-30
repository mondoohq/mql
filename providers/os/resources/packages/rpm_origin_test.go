// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"strings"
	"testing"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// rpm advisories are filed against the SOURCE package: Microsoft's Azure Linux
// feed and Rocky's both name `openssl`, never `openssl-libs`. Without an
// origin, a subpackage built from a differently-named source can only be
// looked up by its own name, and no advisory is ever filed under it.
func TestRpmSourceName(t *testing.T) {
	for in, want := range map[string]string{
		"openssl-3.0.1-23.el9_0.src.rpm":                        "openssl",
		"glibc-2.38-21.azl3.src.rpm":                            "glibc",
		"perl-IO-Socket-SSL-2.073-1.el9.src.rpm":                "perl-IO-Socket-SSL",
		"kernel-5.14.0-70.13.1.el9_0.nosrc.rpm":                 "kernel",
		"python3.9-3.9.14-1.el9_1.1.src.rpm":                    "python3.9",
		"(none)":                                                "",
		"":                                                      "",
		"not-a-source-rpm":                                      "",
		"onlyname.src.rpm":                                      "",
		"name-1.0.src.rpm":                                      "",
		"gpg-pubkey-8483c65d-5ccc5b19":                          "", // gpg-pubkey has no source rpm
		"  openssl-3.0.1-23.el9_0.src.rpm\x00":                  "openssl",
		"openssl-libs-3.0.1-23.el9_0.x86_64.rpm":                "", // a binary rpm is not a source
		"libgcc-11.4.1-3.0.1.el9.src.rpm":                       "libgcc",
		"ca-certificates-2024.2.69_v8.0.303-91.4.el9_4.src.rpm": "ca-certificates",
	} {
		assert.Equal(t, want, rpmSourceName(in), in)
	}
}

// The static path: images, filesystems and devices.
func TestRpmPackageFromDBCarriesItsSource(t *testing.T) {
	pkg := newRpmPackageFromDB(azureLinux3, &rpmdb.PackageInfo{
		Name: "openssl-libs", Version: "3.3.7", Release: "6.azl3", Arch: "x86_64",
		SourceRpm: "openssl-3.3.7-6.azl3.src.rpm",
	}, "/var/lib/rpm/rpmdb.sqlite")
	assert.Equal(t, "openssl", pkg.Origin)
}

// Azure Linux and CBL-Mariner distroless images: the manifest carries
// %{SOURCERPM} in its tenth column.
func TestRpmManifestCarriesTheSource(t *testing.T) {
	pkgs, err := parseRpmManifest(azureLinux3, strings.NewReader(
		readManifestTestdata(t, "rpmmanifest-azurelinux3-distroless.tsv")))
	require.NoError(t, err)
	origins := map[string]string{}
	for _, p := range pkgs {
		origins[p.Name] = p.Origin
	}
	assert.Equal(t, "openssl", origins["openssl-libs"])
	assert.Equal(t, "openssl", origins["openssl"])
	assert.Equal(t, "glibc", origins["glibc"])
}

// The runtime path: rpm -qa on a host or a running container. The source is a
// tagged field ahead of the optional modularity label, so a line from the
// format before it (captured output, an older agent) still parses exactly as
// it did.
func TestRpmQueryFormatCarriesTheSource(t *testing.T) {
	for _, tc := range []struct {
		platform   *inventory.Platform
		modularity string
	}{
		{&inventory.Platform{Name: "redhat", Version: "8", Family: []string{"redhat", "linux", "unix", "os"}}, "perl:5.26:8030020200826163807:c0b5a6c2"},
		{&inventory.Platform{Name: "redhat", Version: "8", Family: []string{"redhat", "linux", "unix", "os"}}, "(none)"},
		{&inventory.Platform{Name: "sles", Version: "15.5", Family: []string{"suse", "linux", "unix", "os"}}, ""},
	} {
		mgr := &RpmPkgManager{platform: tc.platform}
		rendered := renderRpmQueryFormat(mgr.queryFormat(), map[string]string{
			"NAME": "openssl-libs", "EPOCH": "1", "EPOCHNUM": "1", "VERSION": "1.1.1k", "RELEASE": "7.el8_6",
			"ARCH": "x86_64", "VENDOR": "Red Hat, Inc.", "SUMMARY": "A general purpose cryptography library",
			"LICENSE": "OpenSSL and ASL 2.0", "INSTALLTIME": "1700000000",
			"SOURCERPM": "openssl-1.1.1k-7.el8_6.src.rpm", "MODULARITYLABEL": tc.modularity,
		})
		pkgs := ParseRpmPackages(tc.platform, strings.NewReader(rendered))
		require.Len(t, pkgs, 1, "%q", rendered)
		assert.Equal(t, "openssl", pkgs[0].Origin, "%q", rendered)
		if tc.modularity != "" && tc.modularity != "(none)" {
			assert.Contains(t, pkgs[0].PUrl, "rpmmod=", "the modularity label must survive the new field")
		}
	}
}

func TestParseRpmPackagesWithoutTheSourceField(t *testing.T) {
	line := "openssl-libs 1:1.1.1k-7.el8_6 x86_64" + rpmFieldSep + "Red Hat, Inc." + rpmFieldSep +
		"A general purpose cryptography library" + rpmFieldSep + "OpenSSL and ASL 2.0" + rpmFieldSep +
		"1700000000" + rpmFieldSep + "perl:5.26:8030020200826163807:c0b5a6c2\n"
	pkgs := ParseRpmPackages(&inventory.Platform{Name: "redhat", Version: "8"}, strings.NewReader(line))
	require.Len(t, pkgs, 1)
	assert.Equal(t, "", pkgs[0].Origin)
	assert.Contains(t, pkgs[0].PUrl, "rpmmod=", "the modularity label still parses")
}
