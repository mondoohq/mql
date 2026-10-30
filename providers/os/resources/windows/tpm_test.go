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

func TestParseTpm(t *testing.T) {
	t.Run("a present TPM 2.0", func(t *testing.T) {
		input := `{
  "TpmPresent": true,
  "TpmReady": true,
  "TpmEnabled": true,
  "TpmActivated": true,
  "ManufacturerVersion": "7.2.3.1",
  "SpecVersion": "2.0, 0, 1.59"
}`
		info, err := ParseTpm(strings.NewReader(input))
		require.NoError(t, err)
		assert.True(t, info.TpmPresent)
		assert.True(t, info.TpmReady)
		assert.True(t, info.TpmEnabled)
		assert.True(t, info.TpmActivated)
		assert.Equal(t, "7.2.3.1", info.ManufacturerVersion)
		assert.Equal(t, "2.0", info.MajorSpecVersion())
	})

	t.Run("no TPM present", func(t *testing.T) {
		input := `{
  "TpmPresent": false,
  "TpmReady": false,
  "TpmEnabled": false,
  "TpmActivated": false,
  "ManufacturerVersion": "",
  "SpecVersion": ""
}`
		info, err := ParseTpm(strings.NewReader(input))
		require.NoError(t, err)
		assert.False(t, info.TpmPresent)
		assert.Equal(t, "", info.MajorSpecVersion())
	})

	// The script emits an object on every run that succeeds, including on a
	// machine with no TPM, so output that never arrived is not an absent TPM.
	t.Run("empty output is an error, not an absent TPM", func(t *testing.T) {
		info, err := ParseTpm(strings.NewReader("   \n"))
		require.Error(t, err)
		assert.Nil(t, info)
		assert.Contains(t, err.Error(), "no output")
	})
}

// Get-Tpm pads the firmware strings with NUL bytes. The version shape is the
// one a Hyper-V vTPM reports on Windows 10 22H2 and Windows 11 25H2, where
// Win32_Tpm gives the same version as "8224.786.18.4".
func TestParseTpmTrimsNulPadding(t *testing.T) {
	nul19 := strings.Repeat(`\u0000`, 19)
	input := `{
  "TpmPresent": true,
  "ManufacturerVersion": "8224.786.18.4` + nul19 + `",
  "ManufacturerIdTxt": "MSFT\u0000",
  "LockoutHealTime": "16 minutes 40 seconds\u0000",
  "AutoProvisioning": " Enabled\u0000",
  "SpecVersion": "2.0, 0, 1.38\u0000\u0000"
}`
	info, err := ParseTpm(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, "8224.786.18.4", info.ManufacturerVersion)
	assert.Equal(t, "MSFT", info.ManufacturerIdTxt)
	assert.Equal(t, "MSFT", info.Manufacturer())
	assert.Equal(t, "16 minutes 40 seconds", info.LockoutHealTime)
	assert.Equal(t, "Enabled", info.AutoProvisioning)
	assert.Equal(t, "2.0, 0, 1.38", info.SpecVersion)
}

// A Get-Tpm that cannot answer must fail the read instead of reporting the
// cast-to-false flags of an absent TPM.
func TestPSGetTpmFailsInsteadOfReportingAbsent(t *testing.T) {
	assert.NotContains(t, PSGetTpm, "SilentlyContinue")
	assert.Contains(t, PSGetTpm, "$ErrorActionPreference = 'Stop'")
	assert.Contains(t, PSGetTpm, "exit 1")
	// the failure is forgiven only where Win32_Tpm says there is no TPM
	assert.Contains(t, PSGetTpm, "if ($wmi.Count -gt 0)")
	assert.LessOrEqual(t, len(PSGetTpm), PSMaxScriptLength)
}

func TestMajorSpecVersion(t *testing.T) {
	assert.Equal(t, "2.0", (&TpmInfo{SpecVersion: "2.0, 0, 1.59"}).MajorSpecVersion())
	assert.Equal(t, "1.2", (&TpmInfo{SpecVersion: "1.2"}).MajorSpecVersion())
	assert.Equal(t, "", (&TpmInfo{SpecVersion: ""}).MajorSpecVersion())
}

// EC2 instances carry no TPM in the usual configuration, so the present case
// below is verified against constructed input only. Each tag is pinned
// against a payload shaped like the documented Get-Tpm output: a mistyped tag
// yields the zero value, which reads as "not locked out, provisioning
// unknown, clearing permitted" on a machine where none of that is true.
func TestParseTpmLockoutAndProvisioning(t *testing.T) {
	t.Run("a healthy, auto-provisioned TPM 2.0", func(t *testing.T) {
		input := `{
  "TpmPresent": true,
  "TpmReady": true,
  "TpmEnabled": true,
  "TpmActivated": true,
  "ManufacturerVersion": "7.2.3.1",
  "ManufacturerId": 1229346816,
  "ManufacturerIdTxt": "INTC",
  "LockedOut": false,
  "LockoutCount": 0,
  "LockoutHealTime": "10 minutes",
  "AutoProvisioning": "Enabled",
  "OwnerClearDisabled": false,
  "SpecVersion": "2.0, 0, 1.59"
}`
		info, err := ParseTpm(strings.NewReader(input))
		require.NoError(t, err)
		assert.False(t, info.LockedOut)
		assert.Equal(t, int64(0), info.LockoutCount)
		assert.Equal(t, "10 minutes", info.LockoutHealTime)
		assert.Equal(t, "Enabled", info.AutoProvisioning)
		assert.Equal(t, int64(1229346816), info.ManufacturerId)
		assert.Equal(t, "INTC", info.Manufacturer())
		assert.False(t, info.OwnerClearDisabled)
	})

	t.Run("a TPM locked out after failed authorizations", func(t *testing.T) {
		input := `{
  "TpmPresent": true,
  "TpmReady": false,
  "TpmEnabled": true,
  "TpmActivated": true,
  "ManufacturerId": 1095582720,
  "ManufacturerIdTxt": "AMD",
  "LockedOut": true,
  "LockoutCount": 32,
  "LockoutHealTime": "2 hours",
  "AutoProvisioning": "Disabled",
  "OwnerClearDisabled": true,
  "SpecVersion": "2.0, 0, 1.38"
}`
		info, err := ParseTpm(strings.NewReader(input))
		require.NoError(t, err)
		assert.True(t, info.LockedOut)
		assert.Equal(t, int64(32), info.LockoutCount)
		assert.Equal(t, "2 hours", info.LockoutHealTime)
		assert.Equal(t, "Disabled", info.AutoProvisioning)
		assert.True(t, info.OwnerClearDisabled)
		// present but not ready: the pair a Windows 11 readiness or BitLocker
		// check has to distinguish from an absent TPM
		assert.True(t, info.TpmPresent)
		assert.False(t, info.TpmReady)
	})

	t.Run("EnabledForCertainOnly is a third provisioning state", func(t *testing.T) {
		input := `{"TpmPresent":true,"AutoProvisioning":"EnabledForCertainOnly"}`
		info, err := ParseTpm(strings.NewReader(input))
		require.NoError(t, err)
		assert.Equal(t, "EnabledForCertainOnly", info.AutoProvisioning)
	})

	// The absent case, which is what an EC2 instance actually reports.
	t.Run("no TPM leaves the lockout fields at their safe reading", func(t *testing.T) {
		input := `{
  "TpmPresent": false,
  "TpmReady": false,
  "TpmEnabled": false,
  "TpmActivated": false,
  "ManufacturerVersion": "",
  "ManufacturerId": 0,
  "ManufacturerIdTxt": "",
  "LockedOut": false,
  "LockoutCount": 0,
  "LockoutHealTime": "",
  "AutoProvisioning": "",
  "OwnerClearDisabled": false,
  "SpecVersion": ""
}`
		info, err := ParseTpm(strings.NewReader(input))
		require.NoError(t, err)
		assert.False(t, info.TpmPresent)
		assert.False(t, info.LockedOut)
		assert.Equal(t, "", info.AutoProvisioning)
		assert.Equal(t, "", info.Manufacturer())
	})
}

// The firmware pads the vendor identifier to a fixed width, so an untrimmed
// value compares unequal to the vendor name it obviously is.
func TestTpmManufacturer(t *testing.T) {
	assert.Equal(t, "INTC", (&TpmInfo{ManufacturerIdTxt: "INTC"}).Manufacturer())
	assert.Equal(t, "AMD", (&TpmInfo{ManufacturerIdTxt: "AMD "}).Manufacturer())
	assert.Equal(t, "IFX", (&TpmInfo{ManufacturerIdTxt: "IFX\x00"}).Manufacturer())
	assert.Equal(t, "STM", (&TpmInfo{ManufacturerIdTxt: " STM \x00\x00"}).Manufacturer())
	assert.Equal(t, "", (&TpmInfo{ManufacturerIdTxt: ""}).Manufacturer())
}

// The owner authorization value is the secret that authorizes clearing and
// taking ownership of the TPM. Nothing here needs it, so it must not be
// collected: a field that is never fetched cannot be leaked by any query.
func TestPSGetTpmDoesNotCollectOwnerAuth(t *testing.T) {
	assert.NotContains(t, PSGetTpm, "OwnerAuth")
}

// Real Get-Tpm readings from hosts with no TPM, captured through the shipped
// PSGetTpm script. Server 2019 (10.0.17763) produced output identical to 2022,
// so it is covered by the same fixture.
//
// The two versions disagree on what a machine without a TPM reports, which is
// the point of pinning both: on 2016 the TBS service will not start, Get-Tpm
// throws outright, and every field comes back empty (the script forgives that
// failure only because Win32_Tpm has no instance there); on 2019 and later Get-Tpm
// returns an object whose AutoProvisioning is "NotDefined" and whose
// OwnerClearDisabled is true. The second is the trap the resource
// documentation warns about, since a host with no TPM at all reports the same
// value a hardened one would.
func TestParseTpmAbsentServerBaselines(t *testing.T) {
	t.Run("Server 2016, where Get-Tpm itself fails", func(t *testing.T) {
		f, err := os.Open("./testdata/tpm_absent_server2016.json")
		require.NoError(t, err)
		defer f.Close()

		info, err := ParseTpm(f)
		require.NoError(t, err)

		assert.False(t, info.TpmPresent)
		assert.False(t, info.TpmReady)
		assert.False(t, info.TpmEnabled)
		assert.False(t, info.TpmActivated)
		assert.Empty(t, info.AutoProvisioning)
		assert.False(t, info.OwnerClearDisabled)
		assert.Empty(t, info.MajorSpecVersion())
		assert.Empty(t, info.Manufacturer())
	})

	t.Run("Server 2022, where Get-Tpm answers for an absent TPM", func(t *testing.T) {
		f, err := os.Open("./testdata/tpm_absent_server2022.json")
		require.NoError(t, err)
		defer f.Close()

		info, err := ParseTpm(f)
		require.NoError(t, err)

		assert.False(t, info.TpmPresent)
		assert.Equal(t, "NotDefined", info.AutoProvisioning)
		// true on a machine that has no TPM to clear
		assert.True(t, info.OwnerClearDisabled)
		assert.Empty(t, info.MajorSpecVersion())
		assert.Empty(t, info.Manufacturer())
	})
}
