// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mondoo.com/mql/providers/os/resources/plist"
)

// readBundleVersion delegates plist parsing to the helper in
// providers/os/resources/plist; the tests below drive that helper
// directly with the same XML shapes Apple emits in real Info.plist
// files so we exercise the version-extraction logic without needing
// a live macOS host.

const xprotectInfoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.apple.XProtect</string>
    <key>CFBundleShortVersionString</key>
    <string>2186</string>
    <key>CFBundleVersion</key>
    <string>2186</string>
</dict>
</plist>
`

func TestPlistDecode_ExtractsCFBundleShortVersionString(t *testing.T) {
	data, err := plist.Decode(bytes.NewReader([]byte(xprotectInfoPlist)))
	require.NoError(t, err)

	v, ok := data["CFBundleShortVersionString"].(string)
	require.True(t, ok, "CFBundleShortVersionString must decode as string")
	assert.Equal(t, "2186", v)
}

func TestPlistDecode_MissingKeyTreatedAsAbsent(t *testing.T) {
	// A bundle Info.plist without CFBundleShortVersionString — rare
	// but possible for malformed/stub bundles. The reader must return
	// an empty string, not crash.
	const noVersion = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.apple.XProtect</string>
</dict>
</plist>
`
	data, err := plist.Decode(bytes.NewReader([]byte(noVersion)))
	require.NoError(t, err)

	v, _ := data["CFBundleShortVersionString"].(string)
	assert.Equal(t, "", v, "missing key yields empty string")
}

func TestPlistDecode_WrongTypeForVersionTreatedAsAbsent(t *testing.T) {
	// Defensive: if CFBundleShortVersionString is somehow an int
	// (couldn't happen in a real Apple-shipped plist, but the
	// extractor uses a type assertion), the result is "" rather
	// than a panic.
	const intVersion = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleShortVersionString</key>
    <integer>2186</integer>
</dict>
</plist>
`
	data, err := plist.Decode(bytes.NewReader([]byte(intVersion)))
	require.NoError(t, err)

	_, ok := data["CFBundleShortVersionString"].(string)
	assert.False(t, ok, "non-string typed value must not satisfy string assertion")
}

// Path lists are tiny, but assert their order anyway so changes are
// visible — XProtect/MRT paths moved between macOS versions and
// keeping the preferred (newer) path first matters for correctness on
// hosts that have both legacy and modern locations.

func TestXprotectBundlePaths_OrderingAndContents(t *testing.T) {
	require.Len(t, xprotectBundlePaths, 2)
	assert.Equal(t,
		"/Library/Apple/System/Library/CoreServices/XProtect.bundle",
		xprotectBundlePaths[0],
		"modern path must be probed first")
	assert.Equal(t,
		"/System/Library/CoreServices/XProtect.bundle",
		xprotectBundlePaths[1],
		"legacy path is the fallback")
}

func TestMrtBundlePaths_OrderingAndContents(t *testing.T) {
	require.Len(t, mrtBundlePaths, 2)
	assert.Equal(t,
		"/Library/Apple/System/Library/CoreServices/MRT.app",
		mrtBundlePaths[0])
	assert.Equal(t,
		"/System/Library/CoreServices/MRT.app",
		mrtBundlePaths[1])
}
