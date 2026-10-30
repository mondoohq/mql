package detector_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/detector"
)

func TestDarwinRelease(t *testing.T) {
	swVers := `ProductName:	Mac OS X
ProductVersion:	10.13.2
BuildVersion:	17C88
	`

	m, err := detector.ParseDarwinRelease(swVers)
	require.NoError(t, err)

	assert.Equal(t, "Mac OS X", m["ProductName"], "ProductName should be parsed properly")
	assert.Equal(t, "10.13.2", m["ProductVersion"], "ProductVersion should be parsed properly")
	assert.Equal(t, "17C88", m["BuildVersion"], "BuildVersion should be parsed properly")
}

func TestMacOsSystemVersion(t *testing.T) {
	systemVersion := `
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
		<dict>
			<key>ProductBuildVersion</key>
			<string>17C88</string>
			<key>ProductCopyright</key>
			<string>1983-2017 Apple Inc.</string>
			<key>ProductName</key>
			<string>Mac OS X</string>
			<key>ProductUserVisibleVersion</key>
			<string>10.13.2</string>
			<key>ProductVersion</key>
			<string>10.13.2</string>
		</dict>
	</plist>
	`

	m, err := detector.ParseMacOSSystemVersion(systemVersion)
	assert.Nil(t, err)

	assert.Equal(t, "17C88", m["ProductBuildVersion"], "ProductBuildVersion should be parsed properly")
	assert.Equal(t, "1983-2017 Apple Inc.", m["ProductCopyright"], "ProductCopyright should be parsed properly")
	assert.Equal(t, "Mac OS X", m["ProductName"], "ProductName should be parsed properly")
	assert.Equal(t, "10.13.2", m["ProductUserVisibleVersion"], "ProductUserVisibleVersion should be parsed properly")
	assert.Equal(t, "10.13.2", m["ProductVersion"], "ProductVersion should be parsed properly")
}
