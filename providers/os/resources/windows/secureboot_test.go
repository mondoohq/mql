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

func TestParseSecureBoot(t *testing.T) {
	t.Run("UEFI host with Secure Boot enabled", func(t *testing.T) {
		input := `{ "Efi": true, "Enabled": true, "SetupMode": false }`
		status, err := ParseSecureBoot(strings.NewReader(input))
		require.NoError(t, err)
		assert.True(t, status.Efi)
		assert.True(t, status.Enabled)
		assert.False(t, status.SetupMode)
	})

	t.Run("UEFI host with Secure Boot disabled", func(t *testing.T) {
		input := `{ "Efi": true, "Enabled": false, "SetupMode": true }`
		status, err := ParseSecureBoot(strings.NewReader(input))
		require.NoError(t, err)
		assert.True(t, status.Efi)
		assert.False(t, status.Enabled)
		assert.True(t, status.SetupMode)
	})

	t.Run("legacy BIOS host", func(t *testing.T) {
		input := `{ "Efi": false, "Enabled": false, "SetupMode": false }`
		status, err := ParseSecureBoot(strings.NewReader(input))
		require.NoError(t, err)
		assert.False(t, status.Efi)
		assert.False(t, status.Enabled)
		assert.False(t, status.SetupMode)
	})

	t.Run("empty output is treated as a non-UEFI host", func(t *testing.T) {
		status, err := ParseSecureBoot(strings.NewReader("  \n"))
		require.NoError(t, err)
		assert.False(t, status.Efi)
		assert.False(t, status.Enabled)
		assert.False(t, status.SetupMode)
	})
}

// A real reading from a legacy-BIOS host, captured through the shipped
// PSConfirmSecureBoot script on Windows Server 2016, 2019 and 2022, all of
// which produced identical output. Confirm-SecureBootUEFI fails there with
// "Cmdlet not supported on this platform: 0xC0000002", which the script has to
// turn into efi=false rather than into an error.
func TestParseSecureBootLegacyBios(t *testing.T) {
	f, err := os.Open("./testdata/secureboot_legacy_bios.json")
	require.NoError(t, err)
	defer f.Close()

	status, err := ParseSecureBoot(f)
	require.NoError(t, err)

	assert.False(t, status.Efi)
	assert.False(t, status.Enabled)
	assert.False(t, status.SetupMode)
}

// A real reading from a UEFI host: Windows Server 2025 (10.0.26100), where
// Confirm-SecureBootUEFI succeeds and returns False. This is the case the
// legacy-BIOS fixture cannot cover, because there efi and enabled are both
// false for the same reason. Here they have to be told apart: the firmware is
// UEFI, Secure Boot is off, and the platform is in setup mode, which means the
// platform key can be replaced without authentication.
func TestParseSecureBootUefiInSetupMode(t *testing.T) {
	f, err := os.Open("./testdata/secureboot_uefi_setupmode.json")
	require.NoError(t, err)
	defer f.Close()

	status, err := ParseSecureBoot(f)
	require.NoError(t, err)

	assert.True(t, status.Efi)
	assert.False(t, status.Enabled)
	assert.True(t, status.SetupMode)
}
