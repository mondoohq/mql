// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestParseLaunchdOverrides(t *testing.T) {
	// macOS 11 and later.
	got := parseLaunchdOverrides(`disabled services = {
		"com.apple.ODSAgent" => disabled
		"com.apple.screensharing" => enabled
		"com.apple.smbd" => disabled
	}
login-mode services = {
	}
`)
	assert.Equal(t, map[string]bool{
		"com.apple.ODSAgent":      false,
		"com.apple.screensharing": true,
		"com.apple.smbd":          false,
	}, got)

	// Earlier releases printed true for disabled and false for enabled.
	got = parseLaunchdOverrides(`disabled services = {
		"com.apple.screensharing" => false
		"com.apple.smbd" => true
	}
`)
	assert.Equal(t, map[string]bool{
		"com.apple.screensharing": true,
		"com.apple.smbd":          false,
	}, got)
}

const disabledDaemonPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Disabled</key>
	<true/>
	<key>Label</key>
	<string>com.apple.screensharing</string>
</dict>
</plist>
`

// TestSharingSourcesAllOff is shaped on macOS 26.5 with every Sharing toggle
// off: no launchd overrides that enable anything, daemon plists that default
// to Disabled, no Internet Sharing or Remote Management state files, and the
// per-user keys either 0 or never written. AirPlay Receiver is the exception:
// it is on by default, and on the Mac this was taken from it was listening on
// port 7000 with the key unset.
func TestSharingSourcesAllOff(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"launchctl print-disabled system": {Stdout: `disabled services = {
		"com.apple.ODSAgent" => disabled
		"com.apple.screensharing" => disabled
		"com.apple.smbd" => disabled
	}
`},
			"cupsctl":       {Stdout: "_debug_logging=0\n_remote_admin=0\n_remote_any=0\n_share_printers=0\n_user_cancel_any=0\n"},
			hardwareUUIDCmd: {Stdout: ioregOutput},
		},
		Files: map[string]*mock.MockFileData{
			"/Library/Preferences/com.apple.AssetCache.plist": {Content: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Activated</key><false/></dict></plist>
`},
			// Media Sharing written and off; Bluetooth and AirPlay never changed.
			"/Users/alice/Library/Preferences/com.apple.amp.mediasharingd.plist": {Content: prefsPlist("home-sharing-enabled", "public-sharing-enabled")},
		},
	}))
	require.NoError(t, err)
	s := &sharingSources{conn: conn, listUsers: oneUser}

	for name, want := range map[string]bool{
		"Screen Sharing":    false,
		"File Sharing":      false,
		"DVD or CD Sharing": false,
		"Remote Management": false,
		"Printer Sharing":   false,
		"Internet Sharing":  false,
		"Content Caching":   false,
		"Bluetooth Sharing": false,
		"Media Sharing":     false,
		"AirPlay Receiver":  true,
	} {
		got, err := s.flag(name)
		require.NoError(t, err, name)
		assert.Equal(t, want, got, name)
	}
}

// TestSharingSourcesAllOn turns every toggle on through the setting that
// backs it.
func TestSharingSourcesAllOn(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"launchctl print-disabled system": {Stdout: `disabled services = {
		"com.apple.screensharing" => enabled
		"com.apple.smbd" => enabled
	}
`},
			"cupsctl":       {Stdout: "_share_printers=1\n"},
			hardwareUUIDCmd: {Stdout: ioregOutput},
		},
		Files: map[string]*mock.MockFileData{
			// No override for ODSAgent: its daemon plist decides, and this one
			// carries no Disabled key, so launchd runs it.
			"/System/Library/LaunchDaemons/com.apple.ODSAgent.plist": {Content: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Label</key><string>com.apple.ODSAgent</string></dict></plist>
`},
			"/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd": {Content: "enabled\n"},
			"/Library/Preferences/SystemConfiguration/com.apple.nat.plist": {Content: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>NAT</key><dict><key>Enabled</key><integer>1</integer></dict></dict></plist>
`},
			"/Library/Preferences/com.apple.AssetCache.plist": {Content: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Activated</key><true/></dict></plist>
`},
			"/Users/alice/Library/Preferences/ByHost/com.apple.Bluetooth." + testUUID + ".plist":     {Content: prefsPlist("PrefKeyServicesEnabled=1")},
			"/Users/alice/Library/Preferences/com.apple.amp.mediasharingd.plist":                     {Content: prefsPlist("home-sharing-enabled", "public-sharing-enabled=1")},
			"/Users/alice/Library/Preferences/ByHost/com.apple.controlcenter." + testUUID + ".plist": {Content: prefsPlist("AirplayRecieverEnabled")},
		},
	}))
	require.NoError(t, err)
	s := &sharingSources{conn: conn, listUsers: oneUser}

	for name, want := range map[string]bool{
		"Screen Sharing":    true,
		"File Sharing":      true,
		"DVD or CD Sharing": true,
		"Remote Management": true,
		"Printer Sharing":   true,
		"Internet Sharing":  true,
		"Content Caching":   true,
		"Bluetooth Sharing": true,
		"Media Sharing":     true,
		"AirPlay Receiver":  false,
	} {
		got, err := s.flag(name)
		require.NoError(t, err, name)
		assert.Equal(t, want, got, name)
	}
}

// A daemon with no override falls back to its plist's Disabled key.
func TestSharingSourcesLaunchdDefault(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"launchctl print-disabled system": {Stdout: "disabled services = {\n\t}\n"},
		},
		Files: map[string]*mock.MockFileData{
			"/System/Library/LaunchDaemons/com.apple.screensharing.plist": {Content: disabledDaemonPlist},
		},
	}))
	require.NoError(t, err)
	s := &sharingSources{conn: conn}

	got, err := s.flag("Screen Sharing")
	require.NoError(t, err)
	assert.False(t, got, "Disabled=true in the daemon plist and no override")

	got, err = s.flag("File Sharing")
	require.NoError(t, err)
	assert.False(t, got, "daemon not installed")
}

// Anything other than "key not set" is an error, never a silent false.
func TestSharingSourcesUnreadableIsAnError(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"launchctl print-disabled system": {Stderr: "Could not find domain for system", ExitStatus: 113},
			"cupsctl":                         {Stderr: "cupsctl: Unable to connect to server", ExitStatus: 1},
		},
	}))
	require.NoError(t, err)
	s := &sharingSources{conn: conn}

	for _, name := range []string{"Screen Sharing", "Printer Sharing"} {
		_, err := s.flag(name)
		assert.Error(t, err, name)
	}
}

// testUUID is the hardware UUID the ioreg mock reports.
const testUUID = "2BAFE075-9BBA-563A-9DB0-88C141EAB0E5"

var ioregOutput = `+-o J316sAP  <class IOPlatformExpertDevice, id 0x100000200, registered, matched, active, busy 0 (0 ms), retain 30>
    {
      "IOPlatformUUID" = "` + testUUID + `"
      "IOPlatformSerialNumber" = "XXXXXXXXXX"
    }
`

func oneUser() ([]targetUser, error) {
	return []targetUser{{name: "alice", home: "/Users/alice", uid: 501}}, nil
}

// prefsPlist writes a preferences plist. "key=1" sets key to 1, a bare
// "key" sets it to 0.
func prefsPlist(entries ...string) string {
	body := ""
	for _, e := range entries {
		key, val, ok := strings.Cut(e, "=")
		if !ok {
			val = "0"
		}
		body += fmt.Sprintf("<key>%s</key><integer>%s</integer>", key, val)
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>` + body + `</dict></plist>
`
}

// A per-user toggle is on when any user has it on, and a user who never
// changed it has the macOS default.
func TestSharingSourcesPerUserAnyUser(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{hardwareUUIDCmd: {Stdout: ioregOutput}},
		Files: map[string]*mock.MockFileData{
			// alice: everything off, AirPlay turned off.
			"/Users/alice/Library/Preferences/ByHost/com.apple.Bluetooth." + testUUID + ".plist":     {Content: prefsPlist("PrefKeyServicesEnabled")},
			"/Users/alice/Library/Preferences/ByHost/com.apple.controlcenter." + testUUID + ".plist": {Content: prefsPlist("AirplayRecieverEnabled")},
			// bob: Bluetooth Sharing on; AirPlay never changed, so on.
			"/Users/bob/Library/Preferences/ByHost/com.apple.Bluetooth." + testUUID + ".plist": {Content: prefsPlist("PrefKeyServicesEnabled=1")},
			// A file for another Mac's UUID is not this Mac's setting.
			"/Users/alice/Library/Preferences/ByHost/com.apple.Bluetooth.502DBD08-C9E0-5BB4-B954-323719633B51.plist": {Content: prefsPlist("PrefKeyServicesEnabled=1")},
		},
	}))
	require.NoError(t, err)
	twoUsers := func() ([]targetUser, error) {
		return []targetUser{{name: "alice", home: "/Users/alice"}, {name: "bob", home: "/Users/bob"}}, nil
	}
	s := &sharingSources{conn: conn, listUsers: twoUsers}

	for name, want := range map[string]bool{
		"Bluetooth Sharing": true,  // bob
		"Media Sharing":     false, // nobody wrote it
		"AirPlay Receiver":  true,  // bob never changed it
	} {
		got, err := s.flag(name)
		require.NoError(t, err, name)
		assert.Equal(t, want, got, name)
	}

	// With alice alone, only her settings count.
	s = &sharingSources{conn: conn, listUsers: oneUser}
	for name, want := range map[string]bool{
		"Bluetooth Sharing": false, // the other Mac's file is ignored
		"AirPlay Receiver":  false,
	} {
		got, err := s.flag(name)
		require.NoError(t, err, name)
		assert.Equal(t, want, got, name)
	}
}

// A Mac with no real users has the macOS defaults.
func TestSharingSourcesPerUserNoUsers(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{}))
	require.NoError(t, err)
	s := &sharingSources{conn: conn, listUsers: func() ([]targetUser, error) { return nil, nil }}
	got, err := s.flag("AirPlay Receiver")
	require.NoError(t, err)
	assert.True(t, got)
	got, err = s.flag("Bluetooth Sharing")
	require.NoError(t, err)
	assert.False(t, got)
}

// A user whose settings cannot be read is a permission error, never a guess:
// that user might have the sharing on.
func TestSharingSourcesPerUserPermissionDenied(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{}))
	require.NoError(t, err)
	s := &sharingSources{
		conn: conn,
		fs:   &denyFs{Fs: conn.FileSystem(), deny: "/Users/bob/"},
		listUsers: func() ([]targetUser, error) {
			return []targetUser{{name: "alice", home: "/Users/alice"}, {name: "bob", home: "/Users/bob"}}, nil
		},
	}
	_, err = s.flag("Media Sharing")
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrPermission)
	assert.Contains(t, err.Error(), "user bob")
	assert.Contains(t, err.Error(), "requires root")
}

func TestSharingPanelRemoved(t *testing.T) {
	for version, want := range map[string]bool{
		"26.5": true,
		"27.0": true,
		"15.6": false,
		"14":   false,
		"":     false,
		"beta": false,
	} {
		assert.Equal(t, want, sharingPanelRemoved(version), version)
	}
}

// A failed launchctl is not re-run for every field that reads the overrides.
func TestSharingSourcesLaunchdFailureCached(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"launchctl print-disabled system": {Stderr: "Could not find domain for system", ExitStatus: 113},
		},
	}))
	require.NoError(t, err)
	s := &sharingSources{conn: conn}
	_, err1 := s.flag("Screen Sharing")
	_, err2 := s.flag("File Sharing")
	require.Error(t, err1)
	assert.Same(t, err1, err2, "the second field gets the cached error, not a second run")
}

// Remote Management reads its state file through the same file access as
// every other source, so the permission case applies to it too.
func TestSharingSourcesRemoteManagementPermissionDenied(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{}))
	require.NoError(t, err)
	s := &sharingSources{conn: conn, fs: &denyFs{Fs: conn.FileSystem(), deny: "/Library/Application Support/Apple/Remote Desktop/"}}
	_, err = s.flag("Remote Management")
	assert.ErrorIs(t, err, os.ErrPermission)
}
