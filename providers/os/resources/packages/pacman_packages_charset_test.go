// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/resources/packages"
)

var pacmanCharsetPlatform = &inventory.Platform{
	Name:   "arch",
	Arch:   "x86_64",
	Family: []string{"arch", "linux", "unix", "os"},
	Labels: map[string]string{"distro-id": "arch"},
}

// A package the regex cannot match is dropped from the inventory with no error,
// and an absent package is exactly what a vulnerability scan cannot report on.
// The name class used to be `[\w-]`, so every pkgname containing one of the
// other characters pkgname allows -- `.`, `+`, `@` -- went missing.
func TestParsePacmanPackages_NameCharacters(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantName    string
		wantVersion string
	}{
		{
			// stock archlinux:base-devel ships both of these
			name:     "dot in the name",
			line:     "db5.3 5.3.28-5",
			wantName: "db5.3", wantVersion: "5.3.28-5",
		},
		{
			name:     "trailing plus signs",
			line:     "libstdc++ 16.1.1+r595+g171d15ac6959-1",
			wantName: "libstdc++", wantVersion: "16.1.1+r595+g171d15ac6959-1",
		},
		{
			name:     "plus signs after a hyphen",
			line:     "lib32-libstdc++5 3.3.6-8",
			wantName: "lib32-libstdc++5", wantVersion: "3.3.6-8",
		},
		{
			name:     "leading digit",
			line:     "0ad 0.0.26-11",
			wantName: "0ad", wantVersion: "0.0.26-11",
		},
		{
			name:     "digits then hyphen",
			line:     "2048-qt 0.1.6-8",
			wantName: "2048-qt", wantVersion: "0.1.6-8",
		},
		{
			name:     "dot and hyphen together",
			line:     "python3.11-pip 23.2.1-1",
			wantName: "python3.11-pip", wantVersion: "23.2.1-1",
		},
		{
			name:     "at sign",
			line:     "gcc@11 11.4.0-1",
			wantName: "gcc@11", wantVersion: "11.4.0-1",
		},
		{
			name:     "underscore",
			line:     "sdl2_image 2.8.2-1",
			wantName: "sdl2_image", wantVersion: "2.8.2-1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkgs := packages.ParsePacmanPackages(pacmanCharsetPlatform, strings.NewReader(tc.line+"\n"))
			require.Len(t, pkgs, 1, "package was dropped by PACMAN_REGEX")
			assert.Equal(t, tc.wantName, pkgs[0].Name)
			assert.Equal(t, tc.wantVersion, pkgs[0].Version)
			assert.NotEmpty(t, pkgs[0].PUrl)
		})
	}
}

// pkgver carries characters the old class did not enumerate either, and a
// version is matched as a run of non-space precisely so this set never has to
// be guessed at again.
func TestParsePacmanPackages_VersionCharacters(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantVersion string
	}{
		{name: "epoch", line: "zlib 1:1.2.11-2", wantVersion: "1:1.2.11-2"},
		{name: "vcs snapshot", line: "xfce4-pulseaudio-plugin 0.3.2.r13.g553691a-1", wantVersion: "0.3.2.r13.g553691a-1"},
		{name: "plus separated build", line: "usbmuxd 1.1.0+28+g46bdf3e-1", wantVersion: "1.1.0+28+g46bdf3e-1"},
		{name: "tilde pre-release", line: "foo 1.0~beta1-1", wantVersion: "1.0~beta1-1"},
		{name: "pkgrel with a dot", line: "qpdfview 0.4.17beta1-4.1", wantVersion: "0.4.17beta1-4.1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkgs := packages.ParsePacmanPackages(pacmanCharsetPlatform, strings.NewReader(tc.line+"\n"))
			require.Len(t, pkgs, 1, "package was dropped by PACMAN_REGEX")
			assert.Equal(t, tc.wantVersion, pkgs[0].Version)
		})
	}
}

// Widening the name class must not turn pacman's own output into packages.
// pacman writes these on any host whose sync databases are missing, on the
// same stream we parse.
func TestParsePacmanPackages_RejectsNonPackageLines(t *testing.T) {
	noise := strings.Join([]string{
		"",
		"   ",
		"warning: database file for 'core' does not exist (use '-Sy' to download)",
		"error: you cannot perform this operation unless you are root.",
		":: Synchronizing package databases...",
		"error: failed to synchronize all databases (failed to retrieve some files)",
		"-rw-r--r-- 1 root root 0 Jan 1 00:00 file",
	}, "\n")

	pkgs := packages.ParsePacmanPackages(pacmanCharsetPlatform, strings.NewReader(noise+"\n"))
	assert.Empty(t, pkgs, "non-package lines must not be parsed as packages")
}

// A realistic listing: every line survives, in order, alongside the diagnostics
// pacman interleaves with it.
func TestParsePacmanPackages_RealisticListing(t *testing.T) {
	listing := `warning: database file for 'core' does not exist (use '-Sy' to download)
acl 2.3.2-1
db5.3 5.3.28-5
gcc-libs 14.2.1+r134+gab884fffe3fc-1
libstdc++ 16.1.1+r595+g171d15ac6959-1
sdl2_image 2.8.2-1
zlib 1:1.3.1-2
`

	pkgs := packages.ParsePacmanPackages(pacmanCharsetPlatform, strings.NewReader(listing))
	require.Len(t, pkgs, 6, "every package in the listing must be parsed")

	var names []string
	for _, p := range pkgs {
		names = append(names, p.Name)
	}
	assert.Equal(t, []string{"acl", "db5.3", "gcc-libs", "libstdc++", "sdl2_image", "zlib"}, names)
}
