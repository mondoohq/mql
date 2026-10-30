// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixture holds a newer third-party installer run, a newer XProtect data
// blob, a newer command line tools install and a newer Rosetta update than the
// last real macOS update. All four have to be ignored, or a Mac months behind
// on macOS reports as patched days ago.
func TestParseMacosInstallHistory(t *testing.T) {
	f, err := os.Open("./testdata/InstallHistory.plist")
	require.NoError(t, err)
	defer f.Close()

	got, ok, err := ParseMacosInstallHistory(f)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "2026-07-23T10:48:32Z", got.Format(time.RFC3339))
}

func macosPlist(entries string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>` + entries + `
</array>
</plist>`
}

func macosEntry(date, name, process, contentType string, packageIDs ...string) string {
	entry := `
	<dict>
		<key>date</key>
		<date>` + date + `</date>
		<key>displayName</key>
		<string>` + name + `</string>
		<key>processName</key>
		<string>` + process + `</string>`
	if contentType != "" {
		entry += `
		<key>contentType</key>
		<string>` + contentType + `</string>`
	}
	if len(packageIDs) > 0 {
		entry += `
		<key>packageIdentifiers</key>
		<array>`
		for _, id := range packageIDs {
			entry += `
			<string>` + id + `</string>`
		}
		entry += `
		</array>`
	}
	return entry + `
	</dict>`
}

func TestParseMacosInstallHistoryFiltering(t *testing.T) {
	tests := []struct {
		name    string
		entries string
		want    string
	}{
		{
			name:    "softwareupdated os update",
			entries: macosEntry("2026-07-23T10:48:32Z", "macOS 26.5.2", "softwareupdated", ""),
			want:    "2026-07-23T10:48:32Z",
		},
		{
			// Rosetta installs through Software Update whenever an Intel
			// binary first runs; it is not evidence macOS was patched.
			name:    "rosetta alone is not an os update",
			entries: macosEntry("2026-02-18T17:39:44Z", "RosettaUpdateAuto", "softwareupdate", ""),
			want:    "",
		},
		{
			name: "rosetta does not outrank a real update",
			entries: macosEntry("2026-07-23T10:48:32Z", "macOS 26.5.2", "softwareupdated", "") +
				macosEntry("2026-08-20T08:15:09Z", "RosettaUpdateAuto", "softwareupdated", ""),
			want: "2026-07-23T10:48:32Z",
		},
		{
			// Installed by Software Update with no config-data marker, but a
			// developer toolchain rather than a patch to the operating system.
			name:    "command line tools are excluded",
			entries: macosEntry("2026-08-21T09:03:44Z", "Command Line Tools for Xcode", "softwareupdated", ""),
			want:    "",
		},
		{
			name: "command line tools do not outrank a real update",
			entries: macosEntry("2026-07-23T10:48:32Z", "macOS 26.5.2", "softwareupdated", "") +
				macosEntry("2026-08-21T09:03:44Z", "Command Line Tools for Xcode", "softwareupdated", ""),
			want: "2026-07-23T10:48:32Z",
		},
		{
			name:    "config data is excluded",
			entries: macosEntry("2026-08-19T07:01:03Z", "XProtectPlistConfigData", "softwareupdated", "config-data"),
			want:    "",
		},
		{
			name:    "config data named like an update is still excluded",
			entries: macosEntry("2026-08-19T07:01:03Z", "macOS 26.6 Config Data", "softwareupdated", "config-data"),
			want:    "",
		},
		{
			name:    "third party installer is excluded",
			entries: macosEntry("2026-08-25T11:29:02Z", "Mondoo", "installer", ""),
			want:    "",
		},
		{
			name:    "rapid security response counts",
			entries: macosEntry("2026-03-19T00:23:54Z", "macOS Rapid Security Response 26.3.1 (a)", "softwareupdated", ""),
			want:    "2026-03-19T00:23:54Z",
		},
		{
			name:    "bare rapid security response prefix counts",
			entries: macosEntry("2026-03-19T00:23:54Z", "Rapid Security Response 26.3.1 (b)", "softwareupdated", ""),
			want:    "2026-03-19T00:23:54Z",
		},
		{
			name:    "standalone security update of an older release counts",
			entries: macosEntry("2026-04-01T09:00:00Z", "Security Update 2026-002", "softwareupdated", ""),
			want:    "2026-04-01T09:00:00Z",
		},
		{
			// The receipt identifier is the stabler signal: it identifies an
			// OS update even when the display name says nothing recognizable.
			name: "receipt identifier identifies an os update",
			entries: macosEntry("2026-04-01T09:00:00Z", "SecUpd2026-002Sequoia", "softwareupdated", "",
				"com.apple.pkg.update.os.SecUpd2026-002Sequoia.25U4232"),
			want: "2026-04-01T09:00:00Z",
		},
		{
			name: "an unrecognized receipt identifier falls back to the name",
			entries: macosEntry("2026-07-23T10:48:32Z", "macOS 26.5.2", "softwareupdated", "",
				"com.apple.pkg.InstallAssistant.macOS26"),
			want: "2026-07-23T10:48:32Z",
		},
		{
			// "Accept only entries positively identifiable as macOS OS or
			// security updates": a product this code does not recognize is
			// not evidence, even when Apple delivered it.
			name:    "unknown apple product does not count",
			entries: macosEntry("2026-08-22T10:00:00Z", "Pro Video Formats 2.3", "softwareupdated", ""),
			want:    "",
		},
		{
			name:    "safari is not an operating system update",
			entries: macosEntry("2026-08-23T10:00:00Z", "Safari 26.1", "softwareupdated", ""),
			want:    "",
		},
		{
			name:    "a macos name without a version does not count",
			entries: macosEntry("2026-08-24T10:00:00Z", "macOS Installer Assistant", "softwareupdated", ""),
			want:    "",
		},
		{
			name: "newest qualifying entry wins regardless of order",
			entries: macosEntry("2026-07-23T10:48:32Z", "macOS 26.5.2", "softwareupdated", "") +
				macosEntry("2026-03-17T07:18:17Z", "macOS 26.3.1", "softwareupdated", "") +
				macosEntry("2026-08-19T07:01:03Z", "XProtectPlistConfigData", "softwareupdated", "config-data"),
			want: "2026-07-23T10:48:32Z",
		},
		{
			name:    "empty history",
			entries: "",
			want:    "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok, err := ParseMacosInstallHistory(strings.NewReader(macosPlist(test.entries)))
			require.NoError(t, err)
			if test.want == "" {
				assert.False(t, ok)
				assert.True(t, got.IsZero())
				return
			}
			require.True(t, ok)
			assert.Equal(t, test.want, got.Format(time.RFC3339))
		})
	}
}

func TestParseMacosInstallHistoryMalformed(t *testing.T) {
	_, ok, err := ParseMacosInstallHistory(strings.NewReader("not a plist"))
	assert.Error(t, err, "a malformed plist must be reported, not read as an absent record")
	assert.False(t, ok)
}

// A command's stdout does not seek, and the plist decoder needs it to. Feeding
// it one must work rather than fail on the seek.
func TestParseMacosInstallHistoryNonSeekableReader(t *testing.T) {
	plist := macosPlist(macosEntry("2026-07-23T10:48:32Z", "macOS 26.5.2", "softwareupdated", ""))

	got, ok, err := ParseMacosInstallHistory(nonSeekableReader{strings.NewReader(plist)})
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "2026-07-23T10:48:32Z", got.Format(time.RFC3339))
}

type nonSeekableReader struct{ r *strings.Reader }

func (n nonSeekableReader) Read(p []byte) (int, error) { return n.r.Read(p) }
