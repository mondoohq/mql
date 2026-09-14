// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findPkg returns the named package. A parsed BOM also carries the operating
// system as a package, so the subject cannot be assumed to be first.
func findPkg(t *testing.T, bom *Sbom, name string) *Package {
	t.Helper()
	for _, p := range bom.GetPackages() {
		if p.GetName() == name {
			return p
		}
	}
	t.Fatalf("package %q not found in %d packages", name, len(bom.GetPackages()))
	return nil
}

// roundTrip renders a BOM as CycloneDX JSON and parses it back.
func roundTrip(t *testing.T, bom *Sbom) *Sbom {
	t.Helper()
	h := New(FormatCycloneDxJSON)
	buf := bytes.Buffer{}
	require.NoError(t, h.Render(&buf, bom))
	out, err := h.Parse(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	return out
}

func sampleBom() *Sbom {
	return &Sbom{
		Asset: &Asset{
			Name: "debian-host",
			Platform: &Platform{
				Name:    "debian",
				Version: "10.13",
				Arch:    "amd64",
				Title:   "Debian GNU/Linux 10 (buster)",
				Family:  []string{"debian", "linux", "unix", "os"},
			},
		},
		Packages: []*Package{
			{
				Name:         "libc6",
				Version:      "2.28-10+deb10u3",
				Purl:         "pkg:deb/debian/libc6@2.28-10%2Bdeb10u3?arch=amd64&distro=debian-10.13",
				Origin:       "glibc",
				Architecture: "amd64",
				Type:         "deb",
			},
		},
	}
}

// TestCycloneDXKeepsOriginThroughRoundTrip is the property that matters: a
// vulnerability scan of a re-read BOM matches advisories through the source
// package, so losing it turns a vulnerable asset into a clean report.
func TestCycloneDXKeepsOriginThroughRoundTrip(t *testing.T) {
	out := roundTrip(t, sampleBom())

	pkg := findPkg(t, out, "libc6")
	assert.Equal(t, "glibc", pkg.Origin, "the source package must survive; advisories are published against it")
	assert.Equal(t, "amd64", pkg.Architecture)
}

func TestCycloneDXKeepsPlatformDetailThroughRoundTrip(t *testing.T) {
	out := roundTrip(t, sampleBom())

	p := out.Asset.GetPlatform()
	require.NotNil(t, p)
	assert.Equal(t, "debian", p.Name)
	assert.Equal(t, "10.13", p.Version)
	assert.Equal(t, "amd64", p.Arch)
	assert.Equal(t, "Debian GNU/Linux 10 (buster)", p.Title)
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, p.Family)
}

// A document from another tool carries none of these properties and must still
// parse, keeping whatever the reader derived on its own.
func TestCycloneDXWithoutPropertiesStillParses(t *testing.T) {
	bom := sampleBom()
	bom.Asset.Platform.Arch = ""
	bom.Asset.Platform.Title = ""
	bom.Asset.Platform.Family = nil
	bom.Packages[0].Origin = ""
	bom.Packages[0].Architecture = ""

	out := roundTrip(t, bom)
	pkg := findPkg(t, out, "libc6")
	assert.Empty(t, pkg.Origin)
	// familyMap still supplies a family from the platform name
	assert.Equal(t, familyMap["debian"], out.Asset.GetPlatform().GetFamily())
}

// TestFormatRegistry pins that what is advertised, what is accepted and what is
// constructible are one list. New's default used to return the table renderer
// for anything unrecognised, so a misspelled --output produced a table.
func TestFormatRegistry(t *testing.T) {
	for _, name := range []string{
		FormatJson, "cnquery-json", "cnspec-json",
		FormatCycloneDxJSON, FormatCycloneDxXML,
		FormatSpdxJSON, FormatSpdxTagValue,
		FormatList, "list",
	} {
		assert.True(t, IsSupportedFormat(name), "%q must be supported", name)
		assert.NotNil(t, New(name), "%q must build a handler", name)
	}

	assert.False(t, IsSupportedFormat("bogus-format"))
	assert.False(t, IsSupportedFormat(""))

	// Split before asserting. AllFormats returns one comma-joined string, and a
	// substring check on it passes for the wrong reason: "json" is inside
	// "cyclonedx-json", so the assertion would hold even if the entry were gone.
	advertised := strings.Split(AllFormats(), ", ")
	assert.ElementsMatch(t, []string{
		FormatJson, FormatCycloneDxJSON, FormatCycloneDxXML,
		FormatSpdxJSON, FormatSpdxTagValue, FormatList,
	}, advertised, "the advertised list must be exactly the documented formats")

	// aliases are accepted but not advertised
	assert.NotContains(t, advertised, "cnspec-json")
	assert.NotContains(t, advertised, "cnquery-json")
	assert.NotContains(t, advertised, "list")
}

// TestPropertiesStayOnTheirOwnComponent pins which component each kind of
// property belongs to. The operating system is recorded as a package as well as
// the platform, so without this a mondoo:package:* value on the OS component
// would reach that package entry, and a reader restoring "symmetry" would put
// it back.
func TestPropertiesStayOnTheirOwnComponent(t *testing.T) {
	bom := sampleBom()
	out := roundTrip(t, bom)

	// the OS entry is a package too, but carries no package properties
	osPkg := findPkg(t, out, "debian")
	assert.Empty(t, osPkg.Origin, "package properties must not be read off the OS component")
	assert.Empty(t, osPkg.Architecture)

	// while the platform does get its own
	assert.Equal(t, "amd64", out.Asset.GetPlatform().GetArch())

	// and a real package keeps both of its
	pkg := findPkg(t, out, "libc6")
	assert.Equal(t, "glibc", pkg.Origin)
	assert.Equal(t, "amd64", pkg.Architecture)
}
