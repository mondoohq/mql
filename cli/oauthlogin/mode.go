// Copyright Mondoo, Inc. 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"io"
	"runtime"

	"github.com/pkg/browser"
)

var defaultGOOS = runtime.GOOS

// BrowserPlausible reports whether a browser on this machine can reach a
// loopback listener: not over SSH, and on Linux/BSD only with a display.
func BrowserPlausible(getenv func(string) string, goos string) bool {
	if getenv("SSH_CONNECTION") != "" || getenv("SSH_TTY") != "" {
		return false
	}
	switch goos {
	case "windows", "darwin":
		return true
	case "linux", "freebsd", "openbsd", "netbsd", "dragonfly", "solaris", "illumos":
		return getenv("DISPLAY") != "" || getenv("WAYLAND_DISPLAY") != ""
	default:
		return false
	}
}

// DetectMode picks the browser flow when a browser is plausible, the device
// flow otherwise.
func DetectMode(getenv func(string) string, goos string) Mode {
	if BrowserPlausible(getenv, goos) {
		return ModeBrowser
	}
	return ModeDevice
}

// OpenBrowser opens url in the system browser without letting the launcher
// write to the terminal.
func OpenBrowser(url string) error {
	browser.Stdout = io.Discard
	browser.Stderr = io.Discard
	return browser.OpenURL(url)
}
