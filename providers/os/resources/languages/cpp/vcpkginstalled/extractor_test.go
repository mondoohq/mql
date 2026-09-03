// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package vcpkginstalled

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
)

func parse(t *testing.T, body string) languages.Packages {
	t.Helper()
	bom, err := (&Extractor{}).Parse(strings.NewReader(body), "vcpkg_installed/vcpkg/status")
	require.NoError(t, err)
	return bom.Transitive()
}

func TestParseStatus(t *testing.T) {
	body, err := os.ReadFile("testdata/status")
	require.NoError(t, err)

	bom, err := (&Extractor{}).Parse(strings.NewReader(string(body)), "vcpkg_installed/vcpkg/status")
	require.NoError(t, err)

	assert.Nil(t, bom.Root())
	// The status file lists a flat installed set and does not record which
	// entries the project asked for, so claiming a direct set would invent a
	// distinction it does not make.
	assert.Nil(t, bom.Direct())

	pkgs := bom.Transitive()

	// This is the whole point of reading the tree: a manifest defers these
	// versions to the registry baseline and states none.
	fmtPkg := pkgs.Find("fmt")
	require.NotNil(t, fmtPkg)
	assert.Equal(t, "10.2.1", fmtPkg.Version)
	assert.Equal(t, "pkg:vcpkg/fmt@10.2.1?triplet=x64-linux", fmtPkg.Purl)

	// vcpkg appends its own packaging iteration as "3.2.1#2". The port revision
	// is not upstream's version, and an advisory states upstream's.
	openssl := pkgs.Find("openssl")
	require.NotNil(t, openssl)
	assert.Equal(t, "3.2.1", openssl.Version)

	// A feature stanza describes an option of a port, not a port. It carries no
	// version, so reporting it would add a second, version-less curl.
	curls := 0
	for _, p := range pkgs {
		if p.Name == "curl" {
			curls++
			assert.Equal(t, "8.6.0", p.Version)
		}
	}
	assert.Equal(t, 1, curls, "a feature stanza is not a second package")

	// An entry the database still lists after removal is not installed.
	assert.Nil(t, pkgs.Find("boost-system"), "purged entries are not on disk")

	assert.Len(t, pkgs, 4)
}

func TestParseStatusEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"empty file", "", nil},
		{"no trailing blank line", "Package: fmt\nVersion: 1.0\nStatus: install ok installed", []string{"fmt"}},
		{"missing status is not installed", "Package: fmt\nVersion: 1.0\n\n", nil},
		{"deinstall in progress", "Package: fmt\nVersion: 1.0\nStatus: deinstall ok not-installed\n\n", nil},
		{"half-installed", "Package: fmt\nVersion: 1.0\nStatus: install ok half-installed\n\n", nil},
		{"nameless stanza", "Version: 1.0\nStatus: install ok installed\n\n", nil},
		{
			"continuation line is not a field",
			"Package: fmt\nVersion: 1.0\nDescription: one\n two: three\nStatus: install ok installed\n\n",
			[]string{"fmt"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, p := range parse(t, tt.body) {
				got = append(got, p.Name)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestVersionlessInstalledPort pins that a port with no Version field reports as
// installed with an empty version rather than being dropped: it is on disk, and
// saying so with no version is more honest than not saying it.
func TestVersionlessInstalledPort(t *testing.T) {
	pkgs := parse(t, "Package: fmt\nArchitecture: x64-linux\nStatus: install ok installed\n\n")
	require.Len(t, pkgs, 1)
	assert.Empty(t, pkgs[0].Version)
	assert.Equal(t, "pkg:vcpkg/fmt?triplet=x64-linux", pkgs[0].Purl)
}

func TestName(t *testing.T) {
	assert.Equal(t, "vcpkg-installed", (&Extractor{}).Name())
}

// TestParseStatusIsBoundedByLines pins the read bound against the shape that
// defeated the previous one: a file with NO blank line in it. The old counter
// only advanced on a blank-line separator, so such a file was read to the end
// however large it was.
//
// The sentinel stanza sits past the cap, so it is reported only if the reader
// ran past it.
func TestParseStatusIsBoundedByLines(t *testing.T) {
	var b strings.Builder
	b.WriteString("Package: real\nVersion: 1.0\nArchitecture: x64-linux\nStatus: install ok installed\n\n")
	for i := 0; i < maxLines+10; i++ {
		b.WriteString("Description: filler with no blank line\n")
	}
	b.WriteString("\nPackage: past-the-cap\nVersion: 9.9\nStatus: install ok installed\n\n")

	pkgs := parse(t, b.String())
	require.Len(t, pkgs, 1)
	assert.Equal(t, "real", pkgs[0].Name)
	assert.Nil(t, pkgs.Find("past-the-cap"), "the reader ran past its line bound")
}
