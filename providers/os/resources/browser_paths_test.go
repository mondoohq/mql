// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// coveringBrowser returns the name of the configured browser whose data
// directory, under home, contains path.
func coveringBrowser[T any](configs []T, relPath func(T) string, name func(T) string, home, path string) string {
	for _, c := range configs {
		dir := filepath.Join(home, relPath(c))
		if strings.HasPrefix(path, dir+"/") {
			return name(c)
		}
	}
	return ""
}

func TestLinuxChromiumProfileRootsCoverPackagedBrowsers(t *testing.T) {
	rel := func(c browserConfig) string { return c.relPath }
	name := func(c browserConfig) string { return c.name }
	home := "/home/ubuntu"
	cases := map[string]string{
		// Chromium snap 153 on Ubuntu 20.04, 22.04, 24.04 and 26.04
		"/home/ubuntu/snap/chromium/common/chromium/Default/Preferences": "Chromium",
		// Flatpak (Flathub org.chromium.Chromium, com.google.Chrome): XDG
		// config inside ~/.var/app/<app-id>/config
		"/home/ubuntu/.var/app/org.chromium.Chromium/config/chromium/Default/Preferences":  "Chromium",
		"/home/ubuntu/.var/app/com.google.Chrome/config/google-chrome/Default/Preferences": "Google Chrome",
		// Google Chrome .deb
		"/home/ubuntu/.config/google-chrome/Default/Preferences": "Google Chrome",
	}
	for path, want := range cases {
		assert.Equal(t, want, coveringBrowser(browserConfigs["linux"], rel, name, home, path), path)
	}
}

func TestLinuxFirefoxProfileRootsCoverPackagedBrowsers(t *testing.T) {
	rel := func(c firefoxBrowserConfig) string { return c.relPath }
	name := func(c firefoxBrowserConfig) string { return c.name }
	home := "/home/ubuntu"
	cases := map[string]string{
		// Firefox snap 157 on Ubuntu 22.04, 24.04 and 26.04
		"/home/ubuntu/snap/firefox/common/.mozilla/firefox/9td5zg57.default/extensions.json": "Firefox",
		// Flatpak (Flathub org.mozilla.firefox)
		"/home/ubuntu/.var/app/org.mozilla.firefox/.mozilla/firefox/abcd1234.default-release/extensions.json": "Firefox",
		// Firefox .deb / tarball on Ubuntu 16.04 to 20.04
		"/home/ubuntu/.mozilla/firefox/ugko8kss.default-release/extensions.json": "Firefox",
	}
	for path, want := range cases {
		assert.Equal(t, want, coveringBrowser(firefoxBrowserConfigs["linux"], rel, name, home, path), path)
	}
}
