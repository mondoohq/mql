// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package generator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The package entries in testdata/package-sources.json are what the packages
// query returned for a debian:12 container with nginx.org's repository added
// and a local .deb installed, and for alpine:3.20, whose apk packages no
// record attributes.
func TestPackageSourceReachesTheSbom(t *testing.T) {
	report, err := LoadReport("testdata/package-sources.json")
	require.NoError(t, err)
	boms := GenerateBom(report)
	require.Len(t, boms, 1)
	pkgs := boms[0].Packages

	libc := findProtoPkg(pkgs, "libc6")
	require.NotNil(t, libc)
	require.NotNil(t, libc.OsProvided)
	assert.True(t, libc.GetOsProvided())
	assert.Equal(t, "os", libc.GetSource().GetChannel())
	assert.Equal(t, "Debian", libc.GetSource().GetName())
	assert.Equal(t, "http://deb.debian.org/debian", libc.GetSource().GetUrl())

	nginx := findProtoPkg(pkgs, "nginx")
	require.NotNil(t, nginx)
	require.NotNil(t, nginx.OsProvided)
	assert.False(t, nginx.GetOsProvided())
	assert.Equal(t, "vendor-repository", nginx.GetSource().GetChannel())
	assert.Equal(t, "nginx", nginx.GetSource().GetName())

	local := findProtoPkg(pkgs, "acme-agent")
	require.NotNil(t, local)
	assert.Equal(t, "direct", local.GetSource().GetChannel())

	// null is carried as unset, never as false
	busybox := findProtoPkg(pkgs, "busybox")
	require.NotNil(t, busybox)
	assert.Nil(t, busybox.OsProvided)
	assert.Equal(t, "unknown", busybox.GetSource().GetChannel())
}

// The SBOM pack asks where packages came from in a query of its own, so that
// an os provider without osProvided fails that query alone and the package
// list survives. testdata/package-sources-separate.json is the two queries'
// output on the same debian:12 container.
func TestPackageSourceFromSeparateQuery(t *testing.T) {
	report, err := LoadReport("testdata/package-sources-separate.json")
	require.NoError(t, err)
	boms := GenerateBom(report)
	require.Len(t, boms, 1)
	pkgs := boms[0].Packages

	nginx := findProtoPkg(pkgs, "nginx")
	require.NotNil(t, nginx)
	require.NotNil(t, nginx.OsProvided)
	assert.False(t, nginx.GetOsProvided())
	assert.Equal(t, "vendor-repository", nginx.GetSource().GetChannel())
	assert.Equal(t, "nginx", nginx.GetSource().GetName())

	libc := findProtoPkg(pkgs, "libc6")
	require.NotNil(t, libc)
	assert.True(t, libc.GetOsProvided())
	assert.Equal(t, "Debian", libc.GetSource().GetName())

	// the source query adds no packages of its own
	n := 0
	for _, p := range pkgs {
		if p.GetType() == "deb" {
			n++
		}
	}
	assert.Equal(t, 3, n)
}
