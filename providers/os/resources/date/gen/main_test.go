// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Excerpts of the CLDR release-48-2 files, entries copied unchanged.
const windowsZonesExcerpt = `<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE supplementalData SYSTEM "../../common/dtd/ldmlSupplemental.dtd">
<supplementalData>
	<version number="$Revision$"/>
	<windowsZones>
		<mapTimezones otherVersion="7e11800" typeVersion="2021a">
			<!-- (UTC+05:30) Chennai, Kolkata, Mumbai, New Delhi -->
			<mapZone other="India Standard Time" territory="001" type="Asia/Calcutta"/>
			<mapZone other="India Standard Time" territory="IN" type="Asia/Calcutta"/>

			<!-- (UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna -->
			<mapZone other="W. Europe Standard Time" territory="001" type="Europe/Berlin"/>
			<mapZone other="W. Europe Standard Time" territory="AD" type="Europe/Andorra"/>
			<mapZone other="W. Europe Standard Time" territory="CH" type="Europe/Zurich"/>

			<!-- (UTC) Coordinated Universal Time -->
			<mapZone other="UTC" territory="001" type="Etc/UTC"/>
			<mapZone other="UTC" territory="ZZ" type="Etc/UTC Etc/GMT"/>
		</mapTimezones>
	</windowsZones>
</supplementalData>
`

const timezonesExcerpt = `<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE ldmlBCP47 SYSTEM "../../common/dtd/ldmlBCP47.dtd">
<ldmlBCP47>
    <version number="$Revision$"/>
    <keyword>
        <key name="tz" description="Time zone key" alias="timezone">
            <type name="debsngn" description="Busingen, Germany" alias="Europe/Busingen"/>
            <type name="deber" description="Berlin, Germany" alias="Europe/Berlin"/>
            <type name="inccu" description="Kolkata, India" alias="Asia/Calcutta Asia/Kolkata" iana="Asia/Kolkata"/>
            <type name="utc" description="UTC (Coordinated Universal Time)" alias="Etc/UTC Etc/UCT Etc/Universal Etc/Zulu UCT UTC Universal Zulu"/>
        </key>
    </keyword>
</ldmlBCP47>
`

func TestBuildTable(t *testing.T) {
	tbl, err := buildTable([]byte(windowsZonesExcerpt), []byte(timezonesExcerpt))
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		// CLDR's own name is Asia/Calcutta; the iana attribute names the
		// zone the way tzdata does today.
		"India Standard Time": "Asia/Kolkata",
		// Only territory 001 counts, not Andorra or Zurich.
		"W. Europe Standard Time": "Europe/Berlin",
		"UTC":                     "Etc/UTC",
	}, tbl.zones)
	assert.Equal(t, "7e11800", tbl.windowsVersion)
	assert.Equal(t, "2021a", tbl.tzVersion)
}

func TestBuildTableRejectsConflictingDefaults(t *testing.T) {
	doubled := `<supplementalData><windowsZones><mapTimezones>
		<mapZone other="UTC" territory="001" type="Etc/UTC"/>
		<mapZone other="UTC" territory="001" type="Etc/GMT"/>
	</mapTimezones></windowsZones></supplementalData>`
	tz := `<ldmlBCP47><keyword><key name="tz">
		<type name="utc" alias="Etc/UTC"/>
		<type name="gmt" alias="Etc/GMT"/>
	</key></keyword></ldmlBCP47>`

	_, err := buildTable([]byte(doubled), []byte(tz))
	require.Error(t, err)
}

func TestRenderIsValidGo(t *testing.T) {
	src, err := render("release-48-2", &table{zones: map[string]string{"UTC": "Etc/UTC"}}, "UNICODE LICENSE V3\n\nSPDX-License-Identifier: Unicode-3.0\n")
	require.NoError(t, err)
	assert.Contains(t, string(src), `"UTC": "Etc/UTC",`)
	assert.Contains(t, string(src), "//\tSPDX-License-Identifier: Unicode-3.0\n")
}
