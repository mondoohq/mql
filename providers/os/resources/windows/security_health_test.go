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

func TestSecurityHealthPowershell(t *testing.T) {
	r, err := os.Open("./testdata/security_center_health.json")
	require.NoError(t, err)

	health, err := ParseSecurityProviderHealth(r)
	require.NoError(t, err)

	assert.Equal(t, int64(2), health.Firewall.Code)
	assert.Equal(t, "POOR", health.Firewall.Text)
	assert.Equal(t, int64(0), health.AutoUpdate.Code)
	assert.Equal(t, "GOOD", health.AutoUpdate.Text)
	assert.Equal(t, int64(2), health.Uac.Code)
	assert.Equal(t, "POOR", health.Uac.Text)
}

// The Security Center API is absent on Windows Server: wscapi.dll is not
// installed, so the collection script exits non-zero and, if anything reaches
// the parser at all, it is an empty object. Captured from Windows Server 2016,
// 2019 and 2022, all of which produced exactly "{}".
//
// An empty object must not decode to a reading. Every health value is an enum
// whose zero is GOOD, so the all-zero struct would report a clean bill of
// health for the firewall, antivirus, anti-spyware, UAC and the Security
// Center service itself on a host where none of them was ever queried.
func TestSecurityHealthUnavailableIsNotGood(t *testing.T) {
	r, err := os.Open("./testdata/security_center_health_unavailable.json")
	require.NoError(t, err)

	health, err := ParseSecurityProviderHealth(r)
	require.Error(t, err)
	assert.Nil(t, health)
	assert.Contains(t, err.Error(), "did not report")
	// naming the providers is what makes the failure actionable
	for _, name := range []string{"firewall", "antiVirus", "antiSpyware", "uac", "securityCenterService"} {
		assert.Contains(t, err.Error(), name)
	}
}

func TestSecurityHealthEmptyOutput(t *testing.T) {
	health, err := ParseSecurityProviderHealth(strings.NewReader("   \r\n"))
	require.Error(t, err)
	assert.Nil(t, health)
	assert.Contains(t, err.Error(), "no data")
}

// A partial object is the same hazard as an empty one: the providers that are
// missing would read GOOD.
func TestSecurityHealthPartialOutput(t *testing.T) {
	r, err := os.Open("./testdata/security_center_health_partial.json")
	require.NoError(t, err)

	health, err := ParseSecurityProviderHealth(r)
	require.Error(t, err)
	assert.Nil(t, health)
	assert.Contains(t, err.Error(), "antiVirus")
	assert.NotContains(t, err.Error(), "firewall")
}

// WscGetSecurityProviderHealth leaves its out parameter at the wrapper's -1
// sentinel when it fails, and Windows may add health values later. Neither may
// borrow the name of a documented status.
func TestSecurityHealthUnknownCodes(t *testing.T) {
	r, err := os.Open("./testdata/security_center_health_unknown_codes.json")
	require.NoError(t, err)

	health, err := ParseSecurityProviderHealth(r)
	require.NoError(t, err)

	assert.Equal(t, int64(-1), health.Firewall.Code)
	assert.Equal(t, "UNKNOWN", health.Firewall.Text)
	assert.Equal(t, int64(4), health.AutoUpdate.Code)
	assert.Equal(t, "UNKNOWN", health.AutoUpdate.Text)
	// documented values still decode normally
	assert.Equal(t, "GOOD", health.AntiVirus.Text)
	assert.Equal(t, "POOR", health.Uac.Text)
}

// The script builds its C# wrapper with Add-Type, whose -Name and -Namespace
// become C# identifiers. Typographic quotation marks are not string delimiters
// in PowerShell, so they end up inside the identifier and the compile fails,
// which is how the empty object reached the parser in the first place.
func TestSecurityHealthScriptUsesPlainQuotes(t *testing.T) {
	for _, ch := range []string{"‘", "’", "“", "”"} {
		assert.NotContains(t, windowsSecurityHealthScript, ch,
			"typographic quotes break the Add-Type identifiers and the script silently emits an empty object")
	}
	assert.Contains(t, windowsSecurityHealthScript, "-Name 'mondoo_wscapi'")
	assert.Contains(t, windowsSecurityHealthScript, "-Namespace 'Win32'")
	// every failure path has to exit non-zero rather than emit a partial object
	assert.Equal(t, 2, strings.Count(windowsSecurityHealthScript, "exit 1"))
}
