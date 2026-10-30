// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

// fveDword builds a DWORD registry item.
func fveDword(name string, value int64) registry.RegistryKeyItem {
	return registry.RegistryKeyItem{
		Key:   name,
		Value: registry.RegistryKeyValue{Kind: registry.DWORD, Number: value},
	}
}

// fveSz builds a REG_SZ registry item.
func fveSz(name, value string) registry.RegistryKeyItem {
	return registry.RegistryKeyItem{
		Key:   name,
		Value: registry.RegistryKeyValue{Kind: registry.SZ, String: value},
	}
}

// itemsFrom builds the lower-cased name->item map exactly as readFVERegistryKey
// would produce it from the registry.
func itemsFrom(items ...registry.RegistryKeyItem) map[string]registry.RegistryKeyItem {
	m := map[string]registry.RegistryKeyItem{}
	for _, it := range items {
		m[lower(it.Key)] = it
	}
	return m
}

func TestDriveTypeForPrefix(t *testing.T) {
	assert.Equal(t, "operatingSystem", driveTypeForPrefix(fveOSPrefix))
	assert.Equal(t, "fixedData", driveTypeForPrefix(fveFDVPrefix))
	assert.Equal(t, "removableData", driveTypeForPrefix(fveRDVPrefix))
	assert.Equal(t, "unknown", driveTypeForPrefix("unknown"))
}

func TestFveIntPtr(t *testing.T) {
	items := itemsFrom(fveDword("OSRecovery", 0), fveDword("OSManageDRA", 1))

	// present, value 0 must be a non-nil pointer to 0 (distinct from "absent")
	zero := fveIntPtr(items, "OSRecovery")
	require.NotNil(t, zero)
	assert.Equal(t, int64(0), *zero)

	one := fveIntPtr(items, "OSManageDRA")
	require.NotNil(t, one)
	assert.Equal(t, int64(1), *one)

	// absent -> nil
	assert.Nil(t, fveIntPtr(items, "OSPassphrase"))

	// case-insensitive lookup
	require.NotNil(t, fveIntPtr(items, "osrecovery"))
}

func TestFveStringPtr(t *testing.T) {
	items := itemsFrom(fveSz("FDVDiscoveryVolumeType", "FAT32"))

	s := fveStringPtr(items, "FDVDiscoveryVolumeType")
	require.NotNil(t, s)
	assert.Equal(t, "FAT32", *s)

	assert.Nil(t, fveStringPtr(items, "RDVDiscoveryVolumeType"))
}

// rawIntPtr extracts the *int64 carried by an args value, or nil when the
// RawData represents a null value.
func rawIntPtr(t *testing.T, args map[string]*llx.RawData, key string) *int64 {
	t.Helper()
	rd, ok := args[key]
	require.True(t, ok, "missing arg %q", key)
	if rd.Value == nil {
		return nil
	}
	v, ok := rd.Value.(int64)
	require.True(t, ok, "arg %q is not an int64", key)
	return &v
}

// rawBoolPtr extracts the *bool carried by an args value, or nil when the
// RawData represents a null value.
func rawBoolPtr(t *testing.T, args map[string]*llx.RawData, key string) *bool {
	t.Helper()
	rd, ok := args[key]
	require.True(t, ok, "missing arg %q", key)
	if rd.Value == nil {
		return nil
	}
	v, ok := rd.Value.(bool)
	require.True(t, ok, "arg %q is not a bool", key)
	return &v
}

func rawString(t *testing.T, args map[string]*llx.RawData, key string) any {
	t.Helper()
	rd, ok := args[key]
	require.True(t, ok, "missing arg %q", key)
	return rd.Value
}

func TestComputeBitlockerGlobal(t *testing.T) {
	t.Run("present values including zero", func(t *testing.T) {
		items := itemsFrom(
			fveDword("UseAdvancedStartup", 1),
			fveDword("UseEnhancedPin", 1),
			fveDword("EnableBDEWithNoTPM", 0),
			fveDword("DisableExternalDMAUnderLock", 1),
			fveDword("OSAllowSecureBootForIntegrity", 1),
		)
		args := computeBitlockerGlobal(items)

		assert.Equal(t, "windows.bitlocker.policy", args["__id"].Value)
		require.NotNil(t, rawBoolPtr(t, args, "useAdvancedStartup"))
		assert.Equal(t, true, *rawBoolPtr(t, args, "useAdvancedStartup"))
		// explicit 0 stays non-null
		require.NotNil(t, rawBoolPtr(t, args, "enableBdeWithNoTpm"))
		assert.Equal(t, false, *rawBoolPtr(t, args, "enableBdeWithNoTpm"))
		assert.Equal(t, true, *rawBoolPtr(t, args, "osAllowSecureBootForIntegrity"))
	})

	t.Run("absent values are null", func(t *testing.T) {
		args := computeBitlockerGlobal(map[string]registry.RegistryKeyItem{})
		assert.Nil(t, rawBoolPtr(t, args, "useAdvancedStartup"))
		assert.Nil(t, rawBoolPtr(t, args, "useEnhancedPin"))
		assert.Nil(t, rawBoolPtr(t, args, "enableBdeWithNoTpm"))
		assert.Nil(t, rawBoolPtr(t, args, "disableExternalDmaUnderLock"))
		assert.Nil(t, rawBoolPtr(t, args, "osAllowSecureBootForIntegrity"))
	})
}

func TestComputeBitlockerDrive_PrefixRouting(t *testing.T) {
	// every value present for all three prefixes; each drive must pick its own.
	items := itemsFrom(
		fveDword("OSRecovery", 10),
		fveDword("FDVRecovery", 20),
		fveDword("RDVRecovery", 30),
	)

	os := computeBitlockerDrive(items, fveOSPrefix)
	fdv := computeBitlockerDrive(items, fveFDVPrefix)
	rdv := computeBitlockerDrive(items, fveRDVPrefix)

	assert.Equal(t, "operatingSystem", os["driveType"].Value)
	assert.Equal(t, "fixedData", fdv["driveType"].Value)
	assert.Equal(t, "removableData", rdv["driveType"].Value)

	assert.Equal(t, int64(10), *rawIntPtr(t, os, "recovery"))
	assert.Equal(t, int64(20), *rawIntPtr(t, fdv, "recovery"))
	assert.Equal(t, int64(30), *rawIntPtr(t, rdv, "recovery"))

	// ids are unique per drive type
	assert.Equal(t, "windows.bitlocker.policy.driveSettings/operatingSystem", os["__id"].Value)
	assert.Equal(t, "windows.bitlocker.policy.driveSettings/fixedData", fdv["__id"].Value)
	assert.Equal(t, "windows.bitlocker.policy.driveSettings/removableData", rdv["__id"].Value)
}

func TestComputeBitlockerDrive_OSDrive(t *testing.T) {
	// OS drives define the common values but NOT allowUserCert/enforceUserCert/
	// discoveryVolumeType/denyWriteAccess/denyCrossOrg.
	items := itemsFrom(
		fveDword("OSRecovery", 1),
		fveDword("OSManageDRA", 0),
		fveDword("OSRecoveryPassword", 2),
		fveDword("OSRecoveryKey", 2),
		fveDword("OSHideRecoveryPage", 1),
		fveDword("OSActiveDirectoryBackup", 1),
		fveDword("OSActiveDirectoryInfoToStore", 1),
		fveDword("OSRequireActiveDirectoryBackup", 1),
		fveDword("OSHardwareEncryption", 0),
		fveDword("OSPassphrase", 0),
	)
	args := computeBitlockerDrive(items, fveOSPrefix)

	// common values present (including explicit zeros)
	require.NotNil(t, rawIntPtr(t, args, "recovery"))
	assert.Equal(t, int64(1), *rawIntPtr(t, args, "recovery"))
	require.NotNil(t, rawBoolPtr(t, args, "manageDRA"))
	assert.Equal(t, false, *rawBoolPtr(t, args, "manageDRA"))
	assert.Equal(t, int64(2), *rawIntPtr(t, args, "recoveryPassword"))
	assert.Equal(t, int64(2), *rawIntPtr(t, args, "recoveryKey"))
	assert.Equal(t, true, *rawBoolPtr(t, args, "hideRecoveryPage"))
	assert.Equal(t, true, *rawBoolPtr(t, args, "activeDirectoryBackup"))
	assert.Equal(t, int64(1), *rawIntPtr(t, args, "activeDirectoryInfoToStore"))
	assert.Equal(t, true, *rawBoolPtr(t, args, "requireActiveDirectoryBackup"))
	assert.Equal(t, int64(0), *rawIntPtr(t, args, "hardwareEncryption"))
	assert.Equal(t, int64(0), *rawIntPtr(t, args, "passphrase"))

	// fields OS drives don't define are null
	assert.Nil(t, rawBoolPtr(t, args, "allowUserCert"))
	assert.Nil(t, rawBoolPtr(t, args, "enforceUserCert"))
	assert.Nil(t, rawString(t, args, "discoveryVolumeType"))
	assert.Nil(t, rawBoolPtr(t, args, "denyWriteAccess"))
	assert.Nil(t, rawBoolPtr(t, args, "denyCrossOrg"))
}

func TestComputeBitlockerDrive_FixedData(t *testing.T) {
	// fixed data drives add allowUserCert/enforceUserCert/discoveryVolumeType,
	// but still have no denyWriteAccess/denyCrossOrg.
	items := itemsFrom(
		fveDword("FDVRecovery", 1),
		fveDword("FDVAllowUserCert", 1),
		fveDword("FDVEnforceUserCert", 1),
		fveSz("FDVDiscoveryVolumeType", "FAT32"),
	)
	args := computeBitlockerDrive(items, fveFDVPrefix)

	assert.Equal(t, int64(1), *rawIntPtr(t, args, "recovery"))
	assert.Equal(t, true, *rawBoolPtr(t, args, "allowUserCert"))
	assert.Equal(t, true, *rawBoolPtr(t, args, "enforceUserCert"))
	assert.Equal(t, "FAT32", rawString(t, args, "discoveryVolumeType"))

	// removable-only fields are null
	assert.Nil(t, rawBoolPtr(t, args, "denyWriteAccess"))
	assert.Nil(t, rawBoolPtr(t, args, "denyCrossOrg"))

	// unset common field is null
	assert.Nil(t, rawBoolPtr(t, args, "manageDRA"))
}

func TestComputeBitlockerDrive_RemovableData(t *testing.T) {
	// removable data drives define everything, including denyWriteAccess and
	// denyCrossOrg, plus the REG_SZ discoveryVolumeType.
	items := itemsFrom(
		fveDword("RDVRecovery", 1),
		fveDword("RDVAllowUserCert", 0),
		fveDword("RDVEnforceUserCert", 0),
		fveDword("RDVDenyWriteAccess", 1),
		fveDword("RDVDenyCrossOrg", 0),
		fveSz("RDVDiscoveryVolumeType", "Default"),
	)
	args := computeBitlockerDrive(items, fveRDVPrefix)

	assert.Equal(t, int64(1), *rawIntPtr(t, args, "recovery"))
	require.NotNil(t, rawBoolPtr(t, args, "allowUserCert"))
	assert.Equal(t, false, *rawBoolPtr(t, args, "allowUserCert"))
	assert.Equal(t, true, *rawBoolPtr(t, args, "denyWriteAccess"))
	require.NotNil(t, rawBoolPtr(t, args, "denyCrossOrg"))
	assert.Equal(t, false, *rawBoolPtr(t, args, "denyCrossOrg"))
	assert.Equal(t, "Default", rawString(t, args, "discoveryVolumeType"))
}

func TestComputeBitlockerDrive_AllAbsentAreNull(t *testing.T) {
	args := computeBitlockerDrive(map[string]registry.RegistryKeyItem{}, fveRDVPrefix)
	for _, k := range []string{
		"recovery", "recoveryPassword", "recoveryKey",
		"activeDirectoryInfoToStore", "hardwareEncryption", "passphrase",
	} {
		assert.Nil(t, rawIntPtr(t, args, k), "expected %q to be null", k)
	}
	for _, k := range []string{
		"manageDRA", "hideRecoveryPage", "activeDirectoryBackup",
		"requireActiveDirectoryBackup", "allowUserCert", "enforceUserCert",
		"denyWriteAccess", "denyCrossOrg",
	} {
		assert.Nil(t, rawBoolPtr(t, args, k), "expected %q to be null", k)
	}
	assert.Nil(t, rawString(t, args, "discoveryVolumeType"))
	// driveType is always set even with no values
	assert.Equal(t, "removableData", args["driveType"].Value)
}

// available is the escape hatch that lets a policy skip a host where BitLocker
// cannot be read, so it is the one field on the resource that must never
// itself fail. If asking "is BitLocker present here" could error or return
// null, it could not be used to guard the query that does error.
//
// The memo is seeded directly so both outcomes are exercised without a live
// connection; the live behaviour is covered by verification against Windows
// Server 2016, 2019, 2022 and 2025, where the WMI namespace is absent and
// available reports false.
func TestBitlockerAvailableNeverFails(t *testing.T) {
	t.Run("false when the provider could not be read", func(t *testing.T) {
		b := &mqlWindowsBitlocker{}
		b.fetched = true
		b.err = errors.New(`failed to retrieve BitLocker volumes: could not read ` +
			`Win32_EncryptableVolume; the BitLocker feature is not installed on this host`)

		available, err := b.available()
		require.NoError(t, err, "available must not propagate the read failure")
		assert.False(t, available)
	})

	t.Run("true when the provider read, even with no volumes", func(t *testing.T) {
		b := &mqlWindowsBitlocker{}
		b.fetched = true
		b.cachedVolumes = nil

		available, err := b.available()
		require.NoError(t, err)
		assert.True(t, available, "a host whose provider answers is available even with an empty volume list")
	})

	t.Run("true when the provider read volumes", func(t *testing.T) {
		b := &mqlWindowsBitlocker{}
		b.fetched = true
		b.cachedVolumes = []windows.BitLockerVolumeStatus{{DeviceID: "volume-1"}}

		available, err := b.available()
		require.NoError(t, err)
		assert.True(t, available)
	})
}

// A field whose method failed carries the failure and no value, so a locked
// volume never reports the zeroed percentages GetConversionStatus returns
// alongside FVE_E_LOCKED_VOLUME.
func TestBitlockerVolumeArgs(t *testing.T) {
	locked := errors.New("the volume is locked")

	t.Run("failed methods become field errors", func(t *testing.T) {
		args := bitlockerVolumeArgs(&windows.BitLockerVolumeStatus{
			DeviceID:              "volume-1",
			LockStatus:            1,
			ConversionStatusError: locked,
			VersionError:          locked,
			LockStatusError:       locked,
		})
		for _, field := range []string{"conversionStatus", "version", "lockStatus"} {
			require.Contains(t, args, field)
			assert.ErrorIs(t, args[field].Error, locked, field)
			assert.Nil(t, args[field].Value, field)
		}
	})

	t.Run("successful methods keep their values", func(t *testing.T) {
		args := bitlockerVolumeArgs(&windows.BitLockerVolumeStatus{
			DeviceID:   "volume-1",
			LockStatus: 1,
		})
		assert.NoError(t, args["conversionStatus"].Error)
		assert.NoError(t, args["lockStatus"].Error)
		assert.Equal(t, int64(1), args["lockStatus"].Value)
		cs, ok := args["conversionStatus"].Value.(map[string]any)
		require.True(t, ok)
		// a wiping state that was never reported is null in the dict
		assert.Contains(t, cs, "WipingStatus")
		assert.Nil(t, cs["WipingStatus"])
	})
}
