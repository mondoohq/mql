// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// fvePolicyKey is the registry key that backs all BitLocker (FVE) Group Policy
// settings exposed by windows.bitlocker.policy.
const fvePolicyKey = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE`

// bitlocker drive-type prefixes used to route FVE values to the right
// per-drive-type sub-resource.
const (
	fveOSPrefix  = "OS"
	fveFDVPrefix = "FDV"
	fveRDVPrefix = "RDV"
)

// mqlWindowsBitlockerInternal memoizes the single Win32_EncryptableVolume
// read. Both `available` and `volumes` are backed by it, so asking whether
// BitLocker can be read and then reading it costs one PowerShell process
// rather than two.
type mqlWindowsBitlockerInternal struct {
	lock          sync.Mutex
	fetched       bool
	cachedVolumes []windows.BitLockerVolumeStatus
	err           error
}

// read returns the volume statuses, running the collection at most once. The
// error is memoized alongside the data so a host that cannot answer reports
// the same failure to both fields.
func (s *mqlWindowsBitlocker) read() ([]windows.BitLockerVolumeStatus, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.fetched {
		return s.cachedVolumes, s.err
	}
	s.fetched = true

	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		s.err = errors.New("windows.bitlocker is not supported on this connection")
		return nil, s.err
	}
	s.cachedVolumes, s.err = windows.GetBitLockerVolumes(conn)
	return s.cachedVolumes, s.err
}

// available reports whether the BitLocker WMI provider could be read. It is
// the one field on this resource that never fails: it exists so a policy can
// ask "is BitLocker present here" without triggering the very error it is
// trying to avoid, which it could not do if the question itself could error.
func (s *mqlWindowsBitlocker) available() (bool, error) {
	_, err := s.read()
	return err == nil, nil
}

func (s *mqlWindowsBitlocker) volumes() ([]any, error) {
	volumes, err := s.read()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range volumes {
		v := volumes[i]

		o, err := CreateResource(s.MqlRuntime, "windows.bitlocker.volume", bitlockerVolumeArgs(&v))
		if err != nil {
			return nil, err
		}

		// Seed the key protectors the collection script already returned for
		// this volume. They ride along on the single PowerShell run that read
		// the volume itself rather than costing one more per volume.
		volume := o.(*mqlWindowsBitlockerVolume)
		volume.keyProtectorsSeeded = true
		volume.cachedKeyProtectors = v.KeyProtectors
		volume.keyProtectorErr = v.KeyProtectorError

		res = append(res, volume)
	}
	return res, nil
}

// bitlockerVolumeArgs builds the windows.bitlocker.volume fields for one
// volume. A field whose Win32_EncryptableVolume method failed carries that
// failure instead of a value: on a locked volume GetConversionStatus answers
// FVE_E_LOCKED_VOLUME with zeroed percentages, and reporting those would read
// as "0 % encrypted" on a volume that is fully encrypted.
func bitlockerVolumeArgs(v *windows.BitLockerVolumeStatus) map[string]*llx.RawData {
	em, _ := convert.JsonToDict(v.EncryptionMethod)
	ps, _ := convert.JsonToDict(v.ProtectionStatus)

	args := map[string]*llx.RawData{
		"deviceID":           llx.StringData(v.DeviceID),
		"driveLetter":        llx.StringData(v.DriveLetter),
		"encryptionMethod":   llx.DictData(em),
		"persistentVolumeID": llx.StringData(v.PersistentVolumeID),
		"protectionStatus":   llx.DictData(ps),
	}

	if v.ConversionStatusError != nil {
		args["conversionStatus"] = &llx.RawData{Type: types.Dict, Error: v.ConversionStatusError}
	} else {
		cs, _ := convert.JsonToDict(v.ConversionStatus)
		args["conversionStatus"] = llx.DictData(cs)
	}

	if v.VersionError != nil {
		args["version"] = &llx.RawData{Type: types.Dict, Error: v.VersionError}
	} else {
		version, _ := convert.JsonToDict(v.Version)
		args["version"] = llx.DictData(version)
	}

	if v.LockStatusError != nil {
		args["lockStatus"] = &llx.RawData{Type: types.Int, Error: v.LockStatusError}
	} else {
		args["lockStatus"] = llx.IntData(v.LockStatus)
	}
	return args
}

func (s *mqlWindowsBitlockerVolume) id() (string, error) {
	return "bitlocker.volume/" + s.DeviceID.Data, nil
}

// mqlWindowsBitlockerVolumeInternal carries the key protectors that
// windows.bitlocker.volumes already read for this volume, along with the
// reason they could not be read when that is what happened.
type mqlWindowsBitlockerVolumeInternal struct {
	keyProtectorsSeeded bool
	cachedKeyProtectors []windows.BitLockerKeyProtector
	keyProtectorErr     error
}

func (s *mqlWindowsBitlockerVolume) keyProtectors() ([]any, error) {
	// A volume that was never populated by the lister has no protector data
	// at all. Reporting that instead of an empty list keeps a future code path
	// that creates a volume some other way from silently claiming the volume
	// has no key protectors.
	if !s.keyProtectorsSeeded {
		return nil, errors.New("bitlocker key protectors are only available on volumes read from windows.bitlocker.volumes")
	}
	if s.keyProtectorErr != nil {
		return nil, s.keyProtectorErr
	}

	res := make([]any, 0, len(s.cachedKeyProtectors))
	for i := range s.cachedKeyProtectors {
		kp := s.cachedKeyProtectors[i]
		o, err := CreateResource(s.MqlRuntime, "windows.bitlocker.volume.keyProtector", map[string]*llx.RawData{
			// The protector ID is unique within a volume, not across the host,
			// so the cache key has to carry the volume as well.
			"__id":                 llx.StringData("bitlocker.volume/" + s.DeviceID.Data + "/keyProtector/" + kp.ID),
			"keyProtectorId":       llx.StringData(kp.ID),
			"keyProtectorType":     llx.StringData(kp.Type.Text),
			"keyProtectorTypeCode": llx.IntData(kp.Type.Code),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (p *mqlWindowsBitlockerPolicy) id() (string, error) {
	return "windows.bitlocker.policy", nil
}

func (d *mqlWindowsBitlockerPolicyDriveSettings) id() (string, error) {
	return "windows.bitlocker.policy.driveSettings/" + d.DriveType.Data, nil
}

// mqlWindowsBitlockerPolicyInternal caches the FVE policy registry key so the
// global policy fields and all three per-drive-type sub-resources share a single
// registry read rather than re-reading the key once per accessor.
type mqlWindowsBitlockerPolicyInternal struct {
	itemsOnce sync.Once
	items     map[string]registry.RegistryKeyItem
	itemsErr  error
}

// readFVERegistryKey returns the values of the FVE policy registry key as a
// name->item map with lower-cased keys. A missing key yields an empty map (the
// host simply has no BitLocker policy configured); a read failure yields a nil
// map so callers can surface it as null/unknown. The result is read once and
// cached for the lifetime of the resource.
func (p *mqlWindowsBitlockerPolicy) readFVERegistryKey() (map[string]registry.RegistryKeyItem, error) {
	p.itemsOnce.Do(func() {
		p.items, p.itemsErr = p.loadFVERegistryKey()
	})
	return p.items, p.itemsErr
}

// loadFVERegistryKey performs the actual registry read backing readFVERegistryKey.
func (p *mqlWindowsBitlockerPolicy) loadFVERegistryKey() (map[string]registry.RegistryKeyItem, error) {
	items := map[string]registry.RegistryKeyItem{}
	o, err := CreateResource(p.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(fvePolicyKey),
	})
	if err != nil {
		return nil, err
	}
	entries, err := o.(*mqlRegistrykey).getEntries()
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			// the key is absent, but the registry was readable: no policy set
			return items, nil
		}
		log.Debug().Err(err).Str("path", fvePolicyKey).Msg("windows.bitlocker.policy> could not read registry key")
		return nil, err
	}
	for i := range entries {
		items[strings.ToLower(entries[i].Key)] = entries[i]
	}
	return items, nil
}

// fveIntPtr returns a pointer to the DWORD value stored under name, or nil when
// the value is not present. The nil result is what makes "not configured"
// distinguishable from an explicit 0.
func fveIntPtr(items map[string]registry.RegistryKeyItem, name string) *int64 {
	if it, ok := items[strings.ToLower(name)]; ok {
		v := it.Value.Number
		return &v
	}
	return nil
}

// fveStringPtr returns a pointer to the REG_SZ value stored under name, or nil
// when the value is not present.
func fveStringPtr(items map[string]registry.RegistryKeyItem, name string) *string {
	if it, ok := items[strings.ToLower(name)]; ok {
		v := it.Value.String
		return &v
	}
	return nil
}

// driveTypeForPrefix maps an FVE drive-type prefix to the friendly driveType
// value exposed on the sub-resource.
func driveTypeForPrefix(prefix string) string {
	switch prefix {
	case fveOSPrefix:
		return "operatingSystem"
	case fveFDVPrefix:
		return "fixedData"
	case fveRDVPrefix:
		return "removableData"
	default:
		return prefix
	}
}

// computeBitlockerDrive builds the args for a windows.bitlocker.policy.driveSettings
// resource from the raw FVE registry items, routing values by drive-type prefix
// (OS/FDV/RDV). Values that a drive type does not define, or that are not
// configured, become null. This is a pure function so it can be unit-tested
// without a live registry.
func computeBitlockerDrive(items map[string]registry.RegistryKeyItem, prefix string) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":      llx.StringData("windows.bitlocker.policy.driveSettings/" + driveTypeForPrefix(prefix)),
		"driveType": llx.StringData(driveTypeForPrefix(prefix)),

		"recovery":                     llx.IntDataPtr(fveIntPtr(items, prefix+"Recovery")),
		"manageDRA":                    llx.BoolDataPtr(regBoolPtr(items, prefix+"ManageDRA")),
		"recoveryPassword":             llx.IntDataPtr(fveIntPtr(items, prefix+"RecoveryPassword")),
		"recoveryKey":                  llx.IntDataPtr(fveIntPtr(items, prefix+"RecoveryKey")),
		"hideRecoveryPage":             llx.BoolDataPtr(regBoolPtr(items, prefix+"HideRecoveryPage")),
		"activeDirectoryBackup":        llx.BoolDataPtr(regBoolPtr(items, prefix+"ActiveDirectoryBackup")),
		"activeDirectoryInfoToStore":   llx.IntDataPtr(fveIntPtr(items, prefix+"ActiveDirectoryInfoToStore")),
		"requireActiveDirectoryBackup": llx.BoolDataPtr(regBoolPtr(items, prefix+"RequireActiveDirectoryBackup")),
		"hardwareEncryption":           llx.IntDataPtr(fveIntPtr(items, prefix+"HardwareEncryption")),
		"passphrase":                   llx.IntDataPtr(fveIntPtr(items, prefix+"Passphrase")),

		// AllowUserCert / EnforceUserCert exist only for FDV and RDV drives;
		// for OS drives the values are absent and these become null.
		"allowUserCert":   llx.BoolDataPtr(regBoolPtr(items, prefix+"AllowUserCert")),
		"enforceUserCert": llx.BoolDataPtr(regBoolPtr(items, prefix+"EnforceUserCert")),

		// DiscoveryVolumeType is a REG_SZ and exists only for FDV and RDV drives.
		"discoveryVolumeType": llx.StringDataPtr(fveStringPtr(items, prefix+"DiscoveryVolumeType")),

		// DenyWriteAccess / DenyCrossOrg exist only for removable (RDV) drives.
		"denyWriteAccess": llx.BoolDataPtr(regBoolPtr(items, prefix+"DenyWriteAccess")),
		"denyCrossOrg":    llx.BoolDataPtr(regBoolPtr(items, prefix+"DenyCrossOrg")),
	}
	return args
}

// computeBitlockerGlobal builds the args for the windows.bitlocker.policy
// resource itself (the global, non per-drive FVE values). Values that are not
// configured become null. Pure function for unit testing.
func computeBitlockerGlobal(items map[string]registry.RegistryKeyItem) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                          llx.StringData("windows.bitlocker.policy"),
		"useAdvancedStartup":            llx.BoolDataPtr(regBoolPtr(items, "UseAdvancedStartup")),
		"useEnhancedPin":                llx.BoolDataPtr(regBoolPtr(items, "UseEnhancedPin")),
		"enableBdeWithNoTpm":            llx.BoolDataPtr(regBoolPtr(items, "EnableBDEWithNoTPM")),
		"disableExternalDmaUnderLock":   llx.BoolDataPtr(regBoolPtr(items, "DisableExternalDMAUnderLock")),
		"osAllowSecureBootForIntegrity": llx.BoolDataPtr(regBoolPtr(items, "OSAllowSecureBootForIntegrity")),
	}
}

func (s *mqlWindowsBitlocker) policy() (*mqlWindowsBitlockerPolicy, error) {
	// Read the FVE key once to populate the global fields eagerly. The per-drive
	// sub-resources are lazy callbacks that reuse the same cached read.
	p := &mqlWindowsBitlockerPolicy{MqlRuntime: s.MqlRuntime}
	items, err := p.readFVERegistryKey()
	if err != nil {
		return nil, err
	}
	o, err := CreateResource(s.MqlRuntime, "windows.bitlocker.policy", computeBitlockerGlobal(items))
	if err != nil {
		return nil, err
	}
	policy := o.(*mqlWindowsBitlockerPolicy)
	// Seed the created resource's cache with the items we already read so the
	// drive-settings accessors don't read the registry key again.
	policy.itemsOnce.Do(func() {
		policy.items, policy.itemsErr = items, nil
	})
	return policy, nil
}

func (p *mqlWindowsBitlockerPolicy) driveSettings(prefix string) (*mqlWindowsBitlockerPolicyDriveSettings, error) {
	items, err := p.readFVERegistryKey()
	if err != nil {
		return nil, err
	}
	o, err := CreateResource(p.MqlRuntime, "windows.bitlocker.policy.driveSettings", computeBitlockerDrive(items, prefix))
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsBitlockerPolicyDriveSettings), nil
}

func (p *mqlWindowsBitlockerPolicy) operatingSystemDrives() (*mqlWindowsBitlockerPolicyDriveSettings, error) {
	return p.driveSettings(fveOSPrefix)
}

func (p *mqlWindowsBitlockerPolicy) fixedDataDrives() (*mqlWindowsBitlockerPolicyDriveSettings, error) {
	return p.driveSettings(fveFDVPrefix)
}

func (p *mqlWindowsBitlockerPolicy) removableDataDrives() (*mqlWindowsBitlockerPolicyDriveSettings, error) {
	return p.driveSettings(fveRDVPrefix)
}

// windows.bitlocker.policy is reachable by a dotted path that is also its own
// registered resource name: the field `policy` on `windows.bitlocker` and the
// resource `windows.bitlocker.policy` occupy the same path. The compiler
// resolves the longest matching resource name before it considers a field, so
// `windows.bitlocker.policy.useAdvancedStartup` instantiates the resource
// directly and the parent's policy() accessor never runs. The five global FVE
// values are plain schema fields that only that accessor populates, so every
// one stays unset, reports "provider returned no data and no error", and then
// converts as a primitive carrying no type information.
//
// The result reads null, which is worse than an error: `null && null`
// evaluates to true in MQL, so a check written in the dotted form passes on a
// host that was never hardened.
//
// The per-drive-type sub-resources were never affected, because they are
// computed accessors that read the FVE key themselves, and neither was the
// block form `windows.bitlocker { policy { ... } }`, which binds the field
// rather than resolving a resource name.
func initWindowsBitlockerPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}

	parent, err := CreateResource(runtime, "windows.bitlocker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	v := parent.(*mqlWindowsBitlocker).GetPolicy()
	if v.Error != nil {
		return nil, nil, v.Error
	}
	if v.Data == nil {
		return nil, nil, errors.New("could not read the BitLocker policy of this host")
	}
	return args, v.Data, nil
}
