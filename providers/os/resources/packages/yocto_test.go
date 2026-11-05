// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/resources/packages"
)

// SetYoctoPurl rewrites a package's purl to pkg:yocto/core/<name>@<version> on a
// Yocto platform regardless of the backend the package came from. A Yocto image
// can be built with opkg, rpm or deb; the central override in the packages
// resource list() calls this over every listed package so all three backends
// resolve to the Yocto advisories.
func TestSetYoctoPurl(t *testing.T) {
	yocto := &inventory.Platform{Name: "yocto", Arch: "aarch64", Family: []string{"linux", "unix", "os"}}

	// rpm- and deb-backed Yocto packages arrive with a pkg:rpm / pkg:deb purl
	// from their manager; the override replaces it with pkg:yocto.
	for _, tc := range []struct {
		name    string
		pkg     packages.Package
		wantURL string
	}{
		{
			name:    "rpm-backed package",
			pkg:     packages.Package{Name: "curl", Version: "8.7.1", Format: packages.RpmPkgFormat, PUrl: "pkg:rpm/curl@8.7.1"},
			wantURL: "pkg:yocto/core/curl@8.7.1?arch=aarch64",
		},
		{
			name:    "deb-backed package",
			pkg:     packages.Package{Name: "libcurl4", Version: "8.7.1", Format: packages.DpkgPkgFormat, PUrl: "pkg:deb/libcurl4@8.7.1"},
			wantURL: "pkg:yocto/core/libcurl4@8.7.1?arch=aarch64",
		},
		{
			name:    "opkg-backed package",
			pkg:     packages.Package{Name: "openssl", Version: "3.2.1", Format: packages.OpkgPkgFormat},
			wantURL: "pkg:yocto/core/openssl@3.2.1?arch=aarch64",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := tc.pkg
			packages.SetYoctoPurl(yocto, &pkg)
			assert.Equal(t, tc.wantURL, pkg.PUrl)
		})
	}
}

// Off a Yocto platform the override must not touch the purl -- notably opkg's
// other user, OpenWrt, keeps its own (empty) purl.
func TestSetYoctoPurlNonYoctoIsNoop(t *testing.T) {
	openwrt := &inventory.Platform{Name: "openwrt", Arch: "x86_64", Family: []string{"linux", "unix", "os"}}
	pkg := packages.Package{Name: "curl", Version: "8.7.1", Format: packages.OpkgPkgFormat}
	packages.SetYoctoPurl(openwrt, &pkg)
	assert.Empty(t, pkg.PUrl, "a non-yocto platform must not get a yocto purl")

	rpm := packages.Package{Name: "curl", Version: "8.7.1", Format: packages.RpmPkgFormat, PUrl: "pkg:rpm/curl@8.7.1"}
	packages.SetYoctoPurl(&inventory.Platform{Name: "fedora"}, &rpm)
	assert.Equal(t, "pkg:rpm/curl@8.7.1", rpm.PUrl, "a non-yocto platform must keep the backend purl")
}

// A package missing a name or version cannot form a usable purl, so the override
// leaves it untouched rather than emitting pkg:yocto/core/@ or /name@.
func TestSetYoctoPurlIncompletePackage(t *testing.T) {
	yocto := &inventory.Platform{Name: "yocto"}

	noVersion := packages.Package{Name: "curl", Format: packages.RpmPkgFormat, PUrl: "pkg:rpm/curl"}
	packages.SetYoctoPurl(yocto, &noVersion)
	assert.Equal(t, "pkg:rpm/curl", noVersion.PUrl)

	noName := packages.Package{Version: "8.7.1", Format: packages.RpmPkgFormat}
	packages.SetYoctoPurl(yocto, &noName)
	assert.Empty(t, noName.PUrl)

	var nilPlatform *inventory.Platform
	pkg := packages.Package{Name: "curl", Version: "8.7.1", PUrl: "pkg:rpm/curl@8.7.1"}
	packages.SetYoctoPurl(nilPlatform, &pkg)
	assert.Equal(t, "pkg:rpm/curl@8.7.1", pkg.PUrl, "a nil platform must be a no-op")
}
