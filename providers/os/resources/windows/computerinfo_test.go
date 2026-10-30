// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsComputerInfo(t *testing.T) {
	r, err := os.Open("./testdata/computer-info.json")
	require.NoError(t, err)

	items, err := ParseComputerInfo(r)
	assert.Nil(t, err)
	assert.Equal(t, 43, len(items))
}

// TestParseCustomComputerInfoMapsTheRightSources pins the four fields that used
// to be wired to the wrong source. The fixtures are real captured output of
// PSGetComputerInfoCustom from a live host, and each expected value is what
// Get-ComputerInfo reports for that same host, so the fallback and the native
// path are held to the same answer.
//
// Server 2016 and Server 2025 are the two ends of the supported range, and
// they differ on firmware type, which is one of the fields under test.
func TestParseCustomComputerInfoMapsTheRightSources(t *testing.T) {
	tests := []struct {
		fixture string
		// what Get-ComputerInfo reports on the same host
		firmwareType string
		hal          string
	}{
		{fixture: "testdata/custom-computer-info-2016.json", firmwareType: "Bios", hal: "10.0.14393.5786"},
		{fixture: "testdata/custom-computer-info-2025.json", firmwareType: "Uefi", hal: "10.0.26100.32860"},
	}

	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			f, err := os.Open(tt.fixture)
			require.NoError(t, err)
			defer f.Close()

			info, err := ParseCustomComputerInfo(f)
			require.NoError(t, err)

			// Was read out of the WindowsProduct hive, which has no such
			// value, so it was always null. Win32_ComputerSystem.FirmwareType,
			// which the script used to fetch, is empty on every host tested,
			// so the source had to change as well as the mapping.
			assert.Equal(t, tt.firmwareType, info["BiosFirmwareType"])

			// Was the operating system version. The HAL revision is the point
			// of the field and the OS version does not carry it.
			assert.Equal(t, tt.hal, info["OsHardwareAbstractionLayer"])
			assert.NotEqual(t, info["OsVersion"], info["OsHardwareAbstractionLayer"])

			// Was TotalPhysicalMemory: a different quantity in a different
			// unit, so the number was wrong by roughly a factor of a thousand.
			assert.EqualValues(t, 8388608, info["CsPhyicallyInstalledMemory"])
			assert.NotEqual(t, info["CsTotalPhysicalMemory"], info["CsPhyicallyInstalledMemory"])
			total, ok := info["CsTotalPhysicalMemory"].(float64)
			require.True(t, ok)
			assert.Greater(t, total/8388608, float64(900),
				"the two must not be confusable: one is bytes, the other KB, so they differ by about 1024x")

			// Was the boot timestamp, so a field documented as a duration
			// carried a point in time.
			uptime, ok := info["OsUptime"].(map[string]any)
			require.True(t, ok, "uptime must be a duration, not a timestamp")
			assert.Contains(t, uptime, "TotalSeconds")

			// Fields that were already right must stay right.
			assert.NotEmpty(t, info["OsVersion"])
			assert.NotEmpty(t, info["WindowsEditionId"])
			assert.NotEmpty(t, info["BiosManufacturer"])
		})
	}
}

func TestBiosFirmwareType(t *testing.T) {
	assert.Equal(t, "Bios", biosFirmwareType("Legacy"))
	assert.Equal(t, "Uefi", biosFirmwareType("UEFI"))
	assert.Equal(t, "Uefi", biosFirmwareType(" uefi "))

	// "The firmware type could not be read" is not the same claim as "this
	// machine boots BIOS", so an absent or unrecognized value stays null.
	assert.Nil(t, biosFirmwareType(""))
	assert.Nil(t, biosFirmwareType("something else"))
}

// TestParseCustomComputerInfoAbsentSources keeps an unreadable source null
// rather than letting it fall back to a value from somewhere else.
func TestParseCustomComputerInfoAbsentSources(t *testing.T) {
	info, err := ParseCustomComputerInfo(strings.NewReader(
		`{"Bios": {}, "ComputerSystem": {}, "Os": {"Version": "10.0.14393"}, "TimeZone": {}, "WindowsProduct": {}}`))
	require.NoError(t, err)

	assert.Nil(t, info["BiosFirmwareType"])
	assert.Nil(t, info["OsHardwareAbstractionLayer"])
	assert.Nil(t, info["CsPhyicallyInstalledMemory"])
	assert.Nil(t, info["OsUptime"])
}

// TestParseCustomComputerInfoMatchesGetComputerInfo holds the fallback to the
// answer Get-ComputerInfo gives on the same host, for the keys queries read:
// OsProductType and WindowsInstallationType gate policies, OsLanguage picks
// locale-dependent expected values, and CsProcessors and CsTotalPhysicalMemory
// size the hardware. Each pair of fixtures is real captured output of
// PSGetComputerInfoCustom and of PSGetComputerInfo from one host; the de-DE
// host is the case that used to break: its OsLanguage came out as the LCID
// 1031 instead of de-DE, and CsProcessors was always null.
func TestParseCustomComputerInfoMatchesGetComputerInfo(t *testing.T) {
	tests := []struct {
		custom, primary string
		language        string
	}{
		{custom: "testdata/custom-computer-info-2022.json", primary: "testdata/computer-info-2022-host.json", language: "en-US"},
		{custom: "testdata/custom-computer-info-2022-de.json", primary: "testdata/computer-info-2022-de.json", language: "de-DE"},
	}

	for _, tt := range tests {
		t.Run(tt.custom, func(t *testing.T) {
			f, err := os.Open(tt.custom)
			require.NoError(t, err)
			defer f.Close()
			custom, err := ParseCustomComputerInfo(f)
			require.NoError(t, err)

			p, err := os.Open(tt.primary)
			require.NoError(t, err)
			defer p.Close()
			primary, err := ParseComputerInfo(p)
			require.NoError(t, err)

			assert.Equal(t, tt.language, primary["OsLanguage"], "fixture sanity: the host's language")
			for _, key := range []string{
				"OsProductType", "WindowsInstallationType", "OsLanguage", "OsLocale",
				"CsProcessors", "CsTotalPhysicalMemory",
			} {
				assert.Equal(t, primary[key], custom[key], key)
			}
			procs, ok := custom["CsProcessors"].([]any)
			require.True(t, ok, "CsProcessors must be a list, as Get-ComputerInfo reports it")
			require.NotEmpty(t, procs)
			assert.Contains(t, procs[0], "NumberOfCores")
		})
	}
}

// Output of the fallback script from before it resolved culture names has no
// OsLanguageName: the LCID must not stand in for a culture name, so the field
// is null rather than a number no query can compare with.
func TestParseCustomComputerInfoWithoutCultureNames(t *testing.T) {
	info, err := ParseCustomComputerInfo(strings.NewReader(`{"Os": {"OSLanguage": 1031, "Locale": "0407"}}`))
	require.NoError(t, err)
	assert.Nil(t, info["OsLanguage"])
	assert.Nil(t, info["OsLocale"])
	assert.Nil(t, info["CsProcessors"])
}
