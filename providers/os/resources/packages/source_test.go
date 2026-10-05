// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeRepoURL(t *testing.T) {
	tests := map[string]string{
		"https://download.docker.com/linux/debian":            "https://download.docker.com/linux/debian",
		"http://nginx.org/packages/debian/":                   "http://nginx.org/packages/debian",
		"https://user:s3cret@repo.example/apt/":               "https://repo.example/apt",
		"https://pkgs.example.com/deb?token=abc#frag":         "https://pkgs.example.com/deb",
		"https://mirrors.fedoraproject.org/metalink?repo=x&a": "https://mirrors.fedoraproject.org/metalink",
		"http://example.invalid:8080/a_b~c":                   "http://example.invalid:8080/a_b~c",
		// no host: a file path or a mirror list is not an address to report
		"file:///srv/repo":                      "",
		"mirror+file:///etc/apt/mirrors/x.list": "",
		"":                                      "",
		"   ":                                   "",
		"%zz":                                   "",
	}
	for in, want := range tests {
		assert.Equal(t, want, sanitizeRepoURL(in), in)
	}
}

func TestDefaultSource(t *testing.T) {
	assert.Equal(t, Source{Channel: ChannelSnap, Name: "lxd"}, DefaultSource(Package{Name: "lxd", Format: SnapPkgFormat}))
	assert.Equal(t, Source{Channel: ChannelFlatpak, Name: "flathub"}, DefaultSource(Package{Name: "org.gimp.GIMP", Format: FlatpakPkgFormat, Origin: "flathub"}))
	assert.Equal(t, Source{OSProvided: osProvided(false), Channel: ChannelChocolatey, Name: "7zip"}, DefaultSource(Package{Name: "7zip", Format: ChocolateyPkgFormat}))
	assert.Equal(t, Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "Windows Update"}, DefaultSource(Package{Name: "KB5034441", Format: WindowsHotfixPkgFormat}))
	assert.Equal(t, unknownSource(), DefaultSource(Package{Name: "busybox", Format: AlpinePkgFormat}))
	// a source the backend learned while listing wins
	set := Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "x"}
	assert.Equal(t, set, DefaultSource(Package{Name: "busybox", Format: AlpinePkgFormat, source: &set}))
}
