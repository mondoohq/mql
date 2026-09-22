// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
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

// defaultsMissing is what `defaults read` prints for a key that was never set.
func defaultsMissing(domain, key string) *mock.Command {
	return &mock.Command{
		Stderr:     "\nThe domain/default pair of (" + domain + ", " + key + ") does not exist\n",
		ExitStatus: 1,
	}
}

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
			"cupsctl": {Stdout: "_debug_logging=0\n_remote_admin=0\n_remote_any=0\n_share_printers=0\n_user_cancel_any=0\n"},
			"defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled":     defaultsMissing("com.apple.Bluetooth", "PrefKeyServicesEnabled"),
			"defaults export com.apple.amp.mediasharingd -":                             {Stdout: mediaSharingExport(0, 0)},
			"defaults -currentHost read com.apple.controlcenter AirplayRecieverEnabled": defaultsMissing("com.apple.controlcenter", "AirplayRecieverEnabled"),
		},
		Files: map[string]*mock.MockFileData{
			"/Library/Preferences/com.apple.AssetCache.plist": {Content: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Activated</key><false/></dict></plist>
`},
		},
	}))
	require.NoError(t, err)
	s := &sharingSources{conn: conn}

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
			"cupsctl": {Stdout: "_share_printers=1\n"},
			"defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled":     {Stdout: "1\n"},
			"defaults export com.apple.amp.mediasharingd -":                             {Stdout: mediaSharingExport(0, 1)},
			"defaults -currentHost read com.apple.controlcenter AirplayRecieverEnabled": {Stdout: "0\n"},
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
		},
	}))
	require.NoError(t, err)
	s := &sharingSources{conn: conn}

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
			"defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled": {Stdout: "maybe\n"},
		},
	}))
	require.NoError(t, err)
	s := &sharingSources{conn: conn}

	for _, name := range []string{"Screen Sharing", "Printer Sharing", "Bluetooth Sharing"} {
		_, err := s.flag(name)
		assert.Error(t, err, name)
	}
}

// mediaSharingExport is `defaults export com.apple.amp.mediasharingd -` with
// the two toggles set.
func mediaSharingExport(home, public int) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
	<key>home-sharing-enabled</key><integer>%d</integer>
	<key>public-sharing-enabled</key><integer>%d</integer>
</dict></plist>
`, home, public)
}

// A domain never written exports as an empty dict: Media Sharing is off.
func TestSharingSourcesMediaSharingNeverConfigured(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"defaults export com.apple.amp.mediasharingd -": {Stdout: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict/></plist>
`},
		},
	}))
	require.NoError(t, err)
	got, err := (&sharingSources{conn: conn}).flag("Media Sharing")
	require.NoError(t, err)
	assert.False(t, got)
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
