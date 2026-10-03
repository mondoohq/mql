// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// rhel9ProfilesIni is alice's ~/.mozilla/firefox/profiles.ini on RHEL 9.6
// after `firefox -CreateProfile "work /home/alice/ffwork"` (Firefox 140 ESR).
const rhel9ProfilesIni = `[Profile2]
Name=work
IsRelative=0
Path=/home/alice/ffwork

[Profile1]
Name=default
IsRelative=1
Path=n5t1wlvq.default
Default=1

[Profile0]
Name=default-default
IsRelative=1
Path=hxe5hc4j.default-default

[General]
StartWithLastProfile=1
Version=2

[Install11457493C5A56847]
Default=hxe5hc4j.default-default
Locked=1
`

func TestFirefoxAbsoluteProfiles(t *testing.T) {
	assert.Equal(t, []string{"/home/alice/ffwork"}, firefoxAbsoluteProfiles(rhel9ProfilesIni))

	// CRLF, spaces around '=', a Windows profile, and an [Install] section's
	// Default= that must not be read as a profile
	win := "[Profile0]\r\nName=work\r\nIsRelative = 0\r\nPath = D:\\Firefox\\work\r\n\r\n[Install308046B0AF4A39CB]\r\nDefault=D:\\Other\r\n"
	assert.Equal(t, []string{`D:\Firefox\work`}, firefoxAbsoluteProfiles(win))

	// IsRelative=1 and a missing IsRelative are relative to the profile root
	assert.Empty(t, firefoxAbsoluteProfiles("[Profile0]\nPath=abc.default\n\n[Profile1]\nIsRelative=1\nPath=def.default\n"))
	// IsRelative=0 with a relative Path is not an absolute profile
	assert.Empty(t, firefoxAbsoluteProfiles("[Profile0]\nIsRelative=0\nPath=abc.default\n"))
	assert.Empty(t, firefoxAbsoluteProfiles(""))
}

// The snap, flatpak, XDG and legacy profile roots are all named "Firefox",
// and a profile copied from one root into another keeps its directory name.
// Each copy is its own profile and needs its own addon id, or the first one
// found hides the other.
func TestFirefoxAddonKeyUsesProfilePath(t *testing.T) {
	live := firefoxAddonKey("alice", "Firefox", "/home/alice/.config/mozilla/firefox/0rbrtw9p.default-release", "uBlock0@raymondhill.net")
	stale := firefoxAddonKey("alice", "Firefox", "/home/alice/.mozilla/firefox/0rbrtw9p.default-release", "uBlock0@raymondhill.net")
	assert.NotEqual(t, live, stale)
	assert.Equal(t, live, firefoxAddonKey("alice", "Firefox", "/home/alice/.config/mozilla/firefox/0rbrtw9p.default-release", "uBlock0@raymondhill.net"))
}
