// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSharingOutput_TypicalAllOff(t *testing.T) {
	// `system_profiler SPSharingDataType` on a fresh CIS-hardened Mac:
	// every toggle is Off.
	in := `Sharing:

    Computer Name: My Mac
    Bluetooth Sharing: Off
    File Sharing: Off
    Printer Sharing: Off
    Remote Apple Events: Off
    Remote Login: Off
    Remote Management: Off
    Screen Sharing: Off
    Internet Sharing: Off
    Content Caching: Off
    Media Sharing: Off
    AirPlay Receiver: Off
`
	got := parseSharingOutput(in)

	// Every On/Off line should be captured.
	assert.False(t, got["Bluetooth Sharing"])
	assert.False(t, got["File Sharing"])
	assert.False(t, got["Printer Sharing"])
	assert.False(t, got["Remote Apple Events"])
	assert.False(t, got["Remote Login"])
	assert.False(t, got["Remote Management"])
	assert.False(t, got["Screen Sharing"])
	assert.False(t, got["Internet Sharing"])
	assert.False(t, got["Content Caching"])
	assert.False(t, got["Media Sharing"])
	assert.False(t, got["AirPlay Receiver"])

	// `Computer Name: My Mac` is not an On/Off line, so it must not
	// appear in the map at all (otherwise downstream code would index
	// it as a bool).
	_, ok := got["Computer Name"]
	assert.False(t, ok, "non-On/Off lines must be ignored, not stored as false")
}

func TestParseSharingOutput_MixedOnOff(t *testing.T) {
	in := `Sharing:

    Computer Name: My Mac
    Screen Sharing: On
    File Sharing: On
    Remote Management: Off
    AirPlay Receiver: On
    Bluetooth Sharing: Off
`
	got := parseSharingOutput(in)
	assert.True(t, got["Screen Sharing"])
	assert.True(t, got["File Sharing"])
	assert.False(t, got["Remote Management"])
	assert.True(t, got["AirPlay Receiver"])
	assert.False(t, got["Bluetooth Sharing"])
}

func TestParseSharingOutput_EmptyInput(t *testing.T) {
	// Non-Darwin host or missing system_profiler: empty stdout, empty map.
	got := parseSharingOutput("")
	assert.Empty(t, got)
}

func TestParseSharingOutput_OnlyHeader(t *testing.T) {
	// Header but no service lines (impossible in practice but defensive).
	in := "Sharing:\n\n"
	got := parseSharingOutput(in)
	assert.Empty(t, got)
}

func TestParseSharingOutput_NonStandardValueIgnored(t *testing.T) {
	// `Computer Name` and `Local Hostname` have free-text values that
	// happen to look like `Key: Value`. They must not be misparsed
	// as enabled-flags. The "On"/"Off" sentinel filters them.
	in := `    Computer Name: Macbook Pro of Foo Bar
    Local Hostname: macbook.local
    Screen Sharing: Off
`
	got := parseSharingOutput(in)

	// Only the boolean line should land in the map.
	assert.Len(t, got, 1)
	_, ok := got["Screen Sharing"]
	assert.True(t, ok)
}

func TestParseSharingOutput_ColonInValueHandled(t *testing.T) {
	// `Computer Name: Foo: Bar Mac` has a colon inside the value.
	// The parser uses LastIndex of ": " to find the separator, but
	// the result still won't enter the map because the value isn't
	// On/Off.
	in := `    Computer Name: Foo: Bar Mac
    Screen Sharing: On
`
	got := parseSharingOutput(in)
	assert.Len(t, got, 1)
	assert.True(t, got["Screen Sharing"])
}

func TestParseSharingOutput_ExtraWhitespace(t *testing.T) {
	// Real `system_profiler` output uses 4-space indentation; some
	// configs add tabs or extra padding around the value.
	in := "\tScreen Sharing:   On  \n   File Sharing:Off\n"
	got := parseSharingOutput(in)
	assert.True(t, got["Screen Sharing"], "leading whitespace + extra spacing around value")

	// `File Sharing:Off` has no space after the colon, so the `: `
	// separator doesn't match — line is skipped. This is intentional;
	// real macOS output always uses `: ` (colon-space).
	_, ok := got["File Sharing"]
	assert.False(t, ok, "missing colon-space separator means the line is not a key/value")
}

// macOS 26 removed the SPSharingDataType reporter: the command exits 0 and
// prints nothing. That must not read as "every sharing service is off".
func TestParseSharingOutputEmpty(t *testing.T) {
	assert.Empty(t, parseSharingOutput(""))
	assert.Empty(t, parseSharingOutput("\n\n"))
	// A panel that did report keeps working, including entries it omits.
	state := parseSharingOutput("Sharing:\n\n    Computer Name: My Mac\n    File Sharing: On\n    Screen Sharing: Off\n")
	assert.Equal(t, map[string]bool{"File Sharing": true, "Screen Sharing": false}, state)
}
