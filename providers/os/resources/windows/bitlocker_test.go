// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBitlockerStatusPowershell(t *testing.T) {
	r, err := os.Open("./testdata/bitlocker_status.json")
	require.NoError(t, err)

	bitlock, err := ParseWindowsBitlockerStatus(r)
	require.NoError(t, err)
	assert.True(t, len(bitlock) == 2)

	assert.Equal(t, "\\\\?\\Volume{1b7897f7-3916-496c-91de-704fde33dde9}\\", bitlock[0].DeviceID)
	assert.Equal(t, "C:", bitlock[0].DriveLetter)
	assert.Equal(t, "XTS_AES_128", bitlock[0].EncryptionMethod.Text)

	assert.Equal(t, "\\\\?\\Volume{0e4c91e2-80c2-4433-bf7f-31fb65330364}\\", bitlock[1].DeviceID)
	assert.Equal(t, "E:", bitlock[1].DriveLetter)
	assert.Equal(t, "NONE", bitlock[1].EncryptionMethod.Text)
}

func TestBitlockerStatusScriptFitsCommandLine(t *testing.T) {
	// Encode widens the script to UTF-16 and base64s it, roughly tripling it
	// against a command-line cap that depends on the transport. Over the cap
	// the command is rejected before PowerShell runs and the non-zero exit
	// reads as if BitLocker were not installed.
	assert.LessOrEqual(t, len(bitlockerStatusScript), PSMaxScriptLength,
		"the BitLocker collection script has grown past what fits on the command line")
}

func TestKeyProtectorTypeName(t *testing.T) {
	documented := map[int64]string{
		0:  "Unknown",
		1:  "Tpm",
		2:  "ExternalKey",
		3:  "RecoveryPassword",
		4:  "TpmPin",
		5:  "TpmStartupKey",
		6:  "TpmPinStartupKey",
		7:  "PublicKey",
		8:  "Password",
		9:  "TpmCertificate",
		10: "Sid",
	}
	for code, want := range documented {
		assert.Equal(t, want, KeyProtectorTypeName(code), "key protector type %d", code)
	}

	t.Run("an undocumented type is not mapped to a documented one", func(t *testing.T) {
		// A protector type Windows adds later must not be reported as one of
		// the types this code understands: a policy asserting "TPM and PIN
		// only" would otherwise pass on a protector nobody has seen.
		for _, code := range []int64{11, 42, 255, -1} {
			got := KeyProtectorTypeName(code)
			assert.Equal(t, KeyProtectorTypeUnrecognized, got, "key protector type %d", code)
			for _, name := range documented {
				assert.NotEqual(t, name, got, "key protector type %d leaked into %q", code, name)
			}
		}
	})
}

func TestKeyProtectorReadError(t *testing.T) {
	rv := func(v int64) *int64 { return &v }

	t.Run("success is not an error", func(t *testing.T) {
		assert.NoError(t, KeyProtectorReadError("\\\\?\\Volume{a}\\", rv(0)))
	})

	t.Run("FVE_E_NOT_ACTIVATED is an answer, not a failure", func(t *testing.T) {
		// BitLocker was never enabled on the volume, so it genuinely has no
		// key protectors. An empty list is the correct reading here.
		assert.NoError(t, KeyProtectorReadError("\\\\?\\Volume{a}\\", rv(2150694920)))
	})

	t.Run("a missing return value reports the failure", func(t *testing.T) {
		// The WMI call threw, which on a stock host means the session was not
		// elevated. Reporting an empty list instead would read as "no
		// recovery password" on a volume that has one.
		err := KeyProtectorReadError("\\\\?\\Volume{a}\\", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "elevated")
	})

	t.Run("any other return value reports the code", func(t *testing.T) {
		err := KeyProtectorReadError("\\\\?\\Volume{a}\\", rv(2147942487))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "0x80070057")
	})
}

func TestBitlockerKeyProtectorSerializationShapes(t *testing.T) {
	// One payload can carry more than one shape for the same list, so both
	// have to decode to the same protectors.
	const bare = `[{"volume":{"DeviceID":"\\\\?\\Volume{a}\\"},` +
		`"keyProtectors":[{"KeyProtectorID":"{kp-1}","KeyProtectorType":4}],` +
		`"keyProtectorReturnValue":0}]`
	const wrapped = `[{"volume":{"DeviceID":"\\\\?\\Volume{a}\\"},` +
		`"keyProtectors":{"value":[{"KeyProtectorID":"{kp-1}","KeyProtectorType":4}],"Count":1},` +
		`"keyProtectorReturnValue":0}]`

	for name, payload := range map[string]string{"bare array": bare, "Count wrapper": wrapped} {
		t.Run(name, func(t *testing.T) {
			vols, err := ParseWindowsBitlockerStatus(strings.NewReader(payload))
			require.NoError(t, err)
			require.Len(t, vols, 1)
			require.NoError(t, vols[0].KeyProtectorError)
			require.Len(t, vols[0].KeyProtectors, 1,
				"the %s shape decoded to no key protectors on a protected volume", name)
			assert.Equal(t, "{kp-1}", vols[0].KeyProtectors[0].ID)
			assert.Equal(t, int64(4), vols[0].KeyProtectors[0].Type.Code)
			assert.Equal(t, "TpmPin", vols[0].KeyProtectors[0].Type.Text)
		})
	}

	t.Run("a plain slice tag is why the custom decoder exists", func(t *testing.T) {
		// The control: decoding the wrapper into a plain slice does not
		// produce the protectors, which is the bug the custom type prevents.
		var control struct {
			KeyProtectors []psKeyProtector `json:"keyProtectors"`
		}
		err := json.Unmarshal([]byte(`{"keyProtectors":{"value":[{"KeyProtectorID":"{kp-1}","KeyProtectorType":4}],"Count":1}}`), &control)
		assert.Error(t, err)
		assert.Empty(t, control.KeyProtectors)
	})

	t.Run("a single flattened protector is not mistaken for a wrapper", func(t *testing.T) {
		const single = `[{"volume":{"DeviceID":"\\\\?\\Volume{a}\\"},` +
			`"keyProtectors":{"KeyProtectorID":"{kp-1}","KeyProtectorType":3},` +
			`"keyProtectorReturnValue":0}]`
		vols, err := ParseWindowsBitlockerStatus(strings.NewReader(single))
		require.NoError(t, err)
		require.Len(t, vols, 1)
		require.Len(t, vols[0].KeyProtectors, 1)
		assert.Equal(t, "RecoveryPassword", vols[0].KeyProtectors[0].Type.Text)
	})
}

func TestBitlockerKeyProtectorsFixture(t *testing.T) {
	r, err := os.Open("./testdata/bitlocker_status_keyprotectors.json")
	require.NoError(t, err)
	defer r.Close()

	vols, err := ParseWindowsBitlockerStatus(r)
	require.NoError(t, err)
	require.Len(t, vols, 2)

	t.Run("an encrypted volume reports its protectors", func(t *testing.T) {
		require.NoError(t, vols[0].KeyProtectorError)
		require.Len(t, vols[0].KeyProtectors, 2)
		assert.Equal(t, "Tpm", vols[0].KeyProtectors[0].Type.Text)
		assert.Equal(t, "{2E0C2B72-0D30-4B33-9C39-1E6A6E1B7A57}", vols[0].KeyProtectors[0].ID)
		assert.Equal(t, "RecoveryPassword", vols[0].KeyProtectors[1].Type.Text)
		assert.Equal(t, int64(3), vols[0].KeyProtectors[1].Type.Code)
	})

	t.Run("a volume BitLocker was never enabled on reports none", func(t *testing.T) {
		assert.NoError(t, vols[1].KeyProtectorError)
		assert.Empty(t, vols[1].KeyProtectors)
	})
}

func TestBitlockerStatusWithoutKeyProtectors(t *testing.T) {
	// A payload carrying no key protector fields at all cannot be read as "no
	// key protectors": the volume's protectors were never looked at.
	r, err := os.Open("./testdata/bitlocker_status.json")
	require.NoError(t, err)
	defer r.Close()

	vols, err := ParseWindowsBitlockerStatus(r)
	require.NoError(t, err)
	require.Len(t, vols, 2)
	for i := range vols {
		assert.Error(t, vols[i].KeyProtectorError)
		assert.Empty(t, vols[i].KeyProtectors)
	}
}

// The BitLocker WMI provider is registered by the BitLocker feature. On a host
// where the feature was never installed the namespace does not exist, and the
// collection script used to report that as "[]" with exit status 0.
//
// Captured verbatim from Windows Server 2016 (10.0.14393), 2019 (10.0.17763)
// and 2022 (10.0.20348), where
//
//	Get-WmiObject -namespace "Root\cimv2\security\MicrosoftVolumeEncryption" ...
//
// fails with `Invalid namespace` and the script still exits 0 with "[]" on
// stdout. An empty list is the same answer a host with no encryptable volumes
// gives, so a policy could not tell the two apart.
func TestBitlockerMissingNamespaceIsNotAnEmptyList(t *testing.T) {
	stdout, err := os.ReadFile("./testdata/bitlocker_namespace_missing.json")
	require.NoError(t, err)

	// The script now exits non-zero, and that has to reach the caller as an
	// error even though stdout still parses as a valid empty list.
	volumes, err := bitlockerResult(stdout, 1,
		[]byte("could not read Win32_EncryptableVolume; the BitLocker feature is not installed on this host: Invalid namespace\n"))
	require.Error(t, err)
	assert.Nil(t, volumes)
	assert.Contains(t, err.Error(), "BitLocker feature is not installed")

	// and the same bytes on a successful run are still a legitimate empty list
	volumes, err = bitlockerResult(stdout, 0, nil)
	require.NoError(t, err)
	assert.Empty(t, volumes)
}

// A failure that produced no stderr must still be an error rather than an
// empty list, and must say something.
func TestBitlockerNonZeroExitWithoutStderr(t *testing.T) {
	volumes, err := bitlockerResult([]byte("[]"), 5, nil)
	require.Error(t, err)
	assert.Nil(t, volumes)
	assert.Contains(t, err.Error(), "status 5")
}

// Output that never arrived is not an empty list either.
func TestBitlockerEmptyOutput(t *testing.T) {
	volumes, err := bitlockerResult([]byte("  \r\n"), 0, nil)
	require.Error(t, err)
	assert.Nil(t, volumes)
	assert.Contains(t, err.Error(), "no output")
}

// The guard is in the script, not only in Go: without -ErrorAction Stop the
// missing namespace is non-terminating and the script reaches its final
// ConvertTo-Json with an empty collection.
func TestBitlockerScriptFailsOnMissingNamespace(t *testing.T) {
	assert.Contains(t, bitlockerStatusScript, "-ErrorAction Stop")
	assert.Contains(t, bitlockerStatusScript, "exit 1")
}

// Captured on Windows 11 25H2 (build 26200) through the shipped collection
// script, with the volume objects reduced to the properties the parser reads:
// the decrypted system volume C: and a BitLocker-encrypted data volume Q:
// after Lock-BitLocker. On Q: GetConversionStatus answers FVE_E_LOCKED_VOLUME
// with ConversionStatus 0xFFFFFFFF and EncryptionPercentage 0 although the
// volume is fully encrypted, while GetVersion and GetLockStatus still succeed.
func TestBitlockerLockedVolumeFixture(t *testing.T) {
	r, err := os.Open("./testdata/bitlocker_status_locked.json")
	require.NoError(t, err)
	defer r.Close()

	vols, err := ParseWindowsBitlockerStatus(r)
	require.NoError(t, err)
	require.Len(t, vols, 2)

	t.Run("the decrypted volume reads cleanly", func(t *testing.T) {
		c := vols[0]
		assert.Equal(t, "C:", c.DriveLetter)
		require.NoError(t, c.ConversionStatusError)
		require.NoError(t, c.VersionError)
		require.NoError(t, c.LockStatusError)
		assert.Equal(t, "FullyDecrypted", c.ConversionStatus.ConversionStatus.Text)
		// 0xFFFFFFFF is "not reported", not a wiping state
		assert.Nil(t, c.ConversionStatus.WipingStatus)
		assert.Nil(t, c.ConversionStatus.WipingPercentage)
	})

	t.Run("the locked volume reports why its conversion status is missing", func(t *testing.T) {
		q := vols[1]
		assert.Equal(t, "Q:", q.DriveLetter)
		require.Error(t, q.ConversionStatusError)
		assert.Contains(t, q.ConversionStatusError.Error(), "the volume is locked")
		assert.Contains(t, q.ConversionStatusError.Error(), "0x80310000")
		// the methods that did answer on the locked volume keep their values
		require.NoError(t, q.VersionError)
		assert.Equal(t, "Win7", q.Version.Text)
		require.NoError(t, q.LockStatusError)
		assert.Equal(t, int64(1), q.LockStatus)
		require.NoError(t, q.KeyProtectorError)
		require.Len(t, q.KeyProtectors, 2)
		assert.Equal(t, "Password", q.KeyProtectors[0].Type.Text)
	})
}

// Payloads from before the script carried the method return codes cannot
// vouch for the values they hold, the same rule the key protectors follow.
func TestBitlockerMissingReturnValuesAreErrors(t *testing.T) {
	r, err := os.Open("./testdata/bitlocker_status.json")
	require.NoError(t, err)
	defer r.Close()

	vols, err := ParseWindowsBitlockerStatus(r)
	require.NoError(t, err)
	require.NotEmpty(t, vols)
	for i := range vols {
		assert.ErrorContains(t, vols[i].ConversionStatusError, "GetConversionStatus")
		assert.ErrorContains(t, vols[i].VersionError, "GetVersion")
		assert.ErrorContains(t, vols[i].LockStatusError, "GetLockStatus")
	}
}

func TestVolumeMethodError(t *testing.T) {
	rv := func(v int64) *int64 { return &v }
	const dev = "\\\\?\\Volume{a}\\"

	assert.NoError(t, VolumeMethodError(dev, "GetConversionStatus", rv(0)))

	err := VolumeMethodError(dev, "GetConversionStatus", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "elevated")

	err = VolumeMethodError(dev, "GetConversionStatus", rv(2150694912))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "FVE_E_LOCKED_VOLUME")

	err = VolumeMethodError(dev, "GetVersion", rv(2147942487))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GetVersion returned 0x80070057")
}

func TestNewConversionStatus(t *testing.T) {
	t.Run("a reported wiping state keeps its name and percentage", func(t *testing.T) {
		cs := newConversionStatus(2, 40, 2, 15)
		assert.Equal(t, "EncryptionInProgress", cs.ConversionStatus.Text)
		assert.Equal(t, int64(40), cs.EncryptionPercentage)
		require.NotNil(t, cs.WipingStatus)
		assert.Equal(t, "FreeSpaceWipingInProgress", cs.WipingStatus.Text)
		require.NotNil(t, cs.WipingPercentage)
		assert.Equal(t, int64(15), *cs.WipingPercentage)
	})

	t.Run("FreeSpaceNotWiped is a state, not an absence", func(t *testing.T) {
		cs := newConversionStatus(1, 100, 0, 0)
		require.NotNil(t, cs.WipingStatus)
		assert.Equal(t, "FreeSpaceNotWiped", cs.WipingStatus.Text)
	})

	t.Run("an undocumented code is named as such, not blank", func(t *testing.T) {
		cs := newConversionStatus(9, 0, 7, 0)
		assert.Equal(t, StatusUnrecognized, cs.ConversionStatus.Text)
		require.NotNil(t, cs.WipingStatus)
		assert.Equal(t, StatusUnrecognized, cs.WipingStatus.Text)
	})
}

// A method that throws on one volume must not leave the previous volume's
// result in place for the next one to report.
func TestBitlockerScriptResetsPerVolumeResults(t *testing.T) {
	assert.Contains(t, bitlockerStatusScript, "$v = $null; $c = $null; $l = $null")
	assert.Contains(t, bitlockerStatusScript, "ReturnValue = $c.ReturnValue")
	assert.Contains(t, bitlockerStatusScript, "ReturnValue = $v.ReturnValue")
	assert.Contains(t, bitlockerStatusScript, "ReturnValue = $l.ReturnValue")
}
