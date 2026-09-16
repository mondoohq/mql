// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNixSystemClosure(t *testing.T) {
	f, err := os.Open("testdata/nix_system_closure.txt")
	require.NoError(t, err)
	defer f.Close()

	pkgs, err := ParseNixSystemClosure(f)
	require.NoError(t, err)
	require.NotEmpty(t, pkgs)

	byName := map[string][]string{}
	for _, p := range pkgs {
		byName[p.Name] = append(byName[p.Name], p.Version)
	}

	// Real packages from the closure, with the versions nix reports for them.
	tests := []struct {
		name    string
		version string
	}{
		{"acl", "2.4.0"},
		{"attr", "2.6.0"},
		{"bash", "5.3p9"},
		{"bash-interactive", "5.3p9"},
		{"coreutils", "9.11"},
		{"glibc", "2.42-84"},
		{"glibc-locales", "2.42-84"},
		{"util-linux", "2.42.2"},
		{"systemd", "260.2"},
		{"systemd-minimal", "260.2"},
		{"linux", "6.18.50"},
	}
	for _, tt := range tests {
		versions, ok := byName[tt.name]
		require.True(t, ok, "closure has no package %q", tt.name)
		require.Len(t, versions, 1, "%q reported %d times: %v", tt.name, len(versions), versions)
		assert.Equal(t, tt.version, versions[0], "version of %q", tt.name)
		assert.Equal(t, "nix", pkgFormatOf(pkgs, tt.name))
	}

	// acl ships out, bin, doc and man; all four are one package.
	assert.Equal(t, "pkg:nix/acl@2.4.0", pkgPurlOf(pkgs, "acl"))

	// Outputs a single derivation names for itself. Each of these is a real
	// store path in the captured closure, and each must collapse onto the
	// package rather than becoming one of its own.
	for _, tt := range []struct{ name, version string }{
		{"glibc", "2.42-84"},     // glibc-2.42-84-getent
		{"util-linux", "2.42.2"}, // util-linux-2.42.2-lastlog, -login, -mount, -swap
		{"linux", "6.18.50"},     // linux-6.18.50-modules
	} {
		versions := byName[tt.name]
		require.Len(t, versions, 1, "%q reported as %v", tt.name, versions)
		assert.Equal(t, tt.version, versions[0])
	}

	// NixOS builds each systemd unit into the store as its own directory.
	// Those are not installed packages, and nothing named for one may appear.
	for name := range byName {
		assert.False(t, strings.HasPrefix(name, "unit-"),
			"generated systemd unit reported as a package: %q", name)
		assert.False(t, strings.HasPrefix(name, "unit-script-"),
			"generated unit script reported as a package: %q", name)
	}

	// Every package carries a version that starts a real version, and no name
	// appears twice at different versions of the same output.
	for _, p := range pkgs {
		require.NotEmpty(t, p.Version, "package %q has no version", p.Name)
		assert.True(t, p.Version[0] >= '0' && p.Version[0] <= '9',
			"package %q has version %q, which does not start with a digit", p.Name, p.Version)
		assert.NotContains(t, p.Version, ".service", "unit file reported as a version")
		assert.NotContains(t, p.Version, ".conf", "config file reported as a version")
		assert.NotEmpty(t, p.PUrl, "package %q has no purl", p.Name)
	}
}

// The closure is a list of store paths. A line that is not one says the
// command printed something unexpected, and guessing a package out of it would
// invent one.
func TestParseNixSystemClosureSkipsNonStorePaths(t *testing.T) {
	input := strings.Join([]string{
		"/nix/store/0248m4p5xbxby1kg0xma16h44v3qi1i0-libcap-ng-0.9.3",
		"",
		"warning: you do not have Internet access",
		"/etc/passwd",
		"/nix/store/not-a-hash-openssl-3.6.2",
		"/nix/store/61685rbaxmpigwi3z23i33sv3jyfl70q-coreutils-9.11",
	}, "\n")

	pkgs, err := ParseNixSystemClosure(strings.NewReader(input))
	require.NoError(t, err)

	require.Len(t, pkgs, 2)
	names := []string{pkgs[0].Name, pkgs[1].Name}
	assert.Contains(t, names, "libcap-ng")
	assert.Contains(t, names, "coreutils")
}

// A store path that carries no version, or whose version is a unit-file
// suffix, is a generated output rather than a package.
func TestParseNixSystemClosureDropsNonPackages(t *testing.T) {
	input := strings.Join([]string{
		"/nix/store/2ib0zkrvsyk7b8i3mjxriazrpwjnrwam-unit-systemd-modules-load.service",
		"/nix/store/4am3wm9kv904qnljf4sin4bbbsz72f87-unit-systemd-backlight-.service",
		"/nix/store/00hcb86xi0dgd7rcprf8fz1p277aygf6-unit-script-apply-ec2-data-start",
		"/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-etc",
		"/nix/store/61685rbaxmpigwi3z23i33sv3jyfl70q-coreutils-9.11",
	}, "\n")

	pkgs, err := ParseNixSystemClosure(strings.NewReader(input))
	require.NoError(t, err)

	require.Len(t, pkgs, 1)
	assert.Equal(t, "coreutils", pkgs[0].Name)
	assert.Equal(t, "9.11", pkgs[0].Version)
}

func pkgFormatOf(pkgs []Package, name string) string {
	for _, p := range pkgs {
		if p.Name == name {
			return p.Format
		}
	}
	return ""
}

func pkgPurlOf(pkgs []Package, name string) string {
	for _, p := range pkgs {
		if p.Name == name {
			return p.PUrl
		}
	}
	return ""
}
