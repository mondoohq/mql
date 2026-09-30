// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// https://learn.microsoft.com/en-us/windows/win32/secprov/getconversionstatus-win32-encryptablevolume
var conversionStatusValues = map[int64]string{
	0: "FullyDecrypted",
	1: "FullyEncrypted",
	2: "EncryptionInProgress",
	3: "DecryptionInProgress",
	4: "EncryptionPaused",
	5: "DecryptionPaused",
}

// https://learn.microsoft.com/en-us/windows/win32/secprov/getconversionstatus-win32-encryptablevolume
var wipingStatusValues = map[int64]string{
	0: "FreeSpaceNotWiped",
	1: "FreeSpaceWiped",
	2: "FreeSpaceWipingInProgress",
	3: "FreeSpaceWipingPaused",
}

// https://learn.microsoft.com/en-us/windows/win32/secprov/getencryptionmethod-win32-encryptablevolume
var encryptionMethodValues = map[int64]string{
	0: "NONE",
	1: "AES_128_WITH_DIFFUSER",
	2: "AES_256_WITH_DIFFUSER",
	3: "AES_128",
	4: "AES_256",
	5: "HARDWARE_ENCRYPTION",
	6: "XTS_AES_128",
	7: "XTS_AES_256",
}

var fveVersionValues = map[int64]string{
	0: "Unknown",
	1: "Vista",
	2: "Win7",
}

// https://learn.microsoft.com/en-us/windows/win32/secprov/getprotectionstatus-win32-encryptablevolume
var protectionStatusValues = map[int64]string{
	0: "Unprotected",
	1: "Protected",
	2: "Unknown",
}

// https://learn.microsoft.com/en-us/windows/win32/secprov/getkeyprotectortype-win32-encryptablevolume
var keyProtectorTypeValues = map[int64]string{
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

// KeyProtectorTypeUnrecognized is the name reported for a key protector type
// that GetKeyProtectorType did not document when this was written. It is
// deliberately distinct from the documented "Unknown" (type 0), so a value
// Windows adds later cannot be mistaken for one this code understands. The
// numeric code stays available alongside it.
const KeyProtectorTypeUnrecognized = "Unrecognized"

// KeyProtectorTypeName maps a GetKeyProtectorType code to its name. A code
// outside the documented set yields KeyProtectorTypeUnrecognized rather than
// the name of a neighboring type.
func KeyProtectorTypeName(code int64) string {
	if name, ok := keyProtectorTypeValues[code]; ok {
		return name
	}
	return KeyProtectorTypeUnrecognized
}

// fveErrNotActivated is FVE_E_NOT_ACTIVATED (0x80310008): BitLocker is not
// enabled on the volume. GetKeyProtectors reports it instead of an empty list,
// and it is the one non-zero return value that is an answer rather than a
// failure, so it maps to "this volume has no key protectors".
const fveErrNotActivated = 2150694920

// KeyProtectorReadError reports why a volume's key protectors could not be
// enumerated, or nil when the list that came back can be trusted.
//
// A nil returnValue means the WMI call itself threw, which on a stock host
// means the session was not elevated. Reporting that as an error matters more
// than it looks: the alternative is an empty list, and an empty list reads as
// "this volume has no recovery password" on a volume that has one.
func KeyProtectorReadError(deviceID string, returnValue *int64) error {
	if returnValue == nil {
		return errors.New("could not query the BitLocker key protectors of " + deviceID +
			"; reading them requires an elevated session")
	}
	switch *returnValue {
	case 0, fveErrNotActivated:
		return nil
	}
	return fmt.Errorf("could not read the BitLocker key protectors of %s: Win32_EncryptableVolume.GetKeyProtectors returned 0x%08X",
		deviceID, uint32(*returnValue))
}

// The Win32_EncryptableVolume class is registered by the BitLocker feature, so
// on a host where the feature is not installed the namespace does not exist at
// all. Get-WmiObject reports that as a non-terminating error, which left
// $encryptedVolumes empty and the script emitting "[]" with exit status 0. An
// empty list is the same answer a host with no encryptable volumes gives, so
// `windows.bitlocker.volumes.all(...)` and `.none(...)` passed vacuously on
// every host that has never had BitLocker installed. -ErrorAction Stop turns
// the missing namespace into a failure the caller can see.
//
// The per-volume method calls deliberately keep the default preference: one
// volume that will not answer must not take the whole reading down with it.
const bitlockerStatusScript = `
try {
	$encryptedVolumes = @(Get-WmiObject -namespace "Root\cimv2\security\MicrosoftVolumeEncryption" -ClassName "Win32_Encryptablevolume" -ErrorAction Stop)
} catch {
	[Console]::Error.WriteLine("could not read Win32_EncryptableVolume; the BitLocker feature is not installed on this host: " + $_.Exception.Message)
	exit 1
}

$bitlockerStatus = @()

foreach ($volume in $encryptedVolumes) {
	
	$wmiVersion = $volume.GetVersion()
	$version = New-Object psobject -Property @{
	  "Version" =  $wmiVersion.Version;
	}
	
	$wmiConversionStatus = $volume.GetConversionStatus()
	$conversionStatus = New-Object psobject -Property @{
	  "ConversionStatus" =  $wmiConversionStatus.ConversionStatus;
	  "EncryptionFlags" =  $wmiConversionStatus.EncryptionFlags;
	  "EncryptionPercentage" =  $wmiConversionStatus.EncryptionPercentage;
	  "WipingPercentage"  = $wmiConversionStatus.WipingPercentage;
	  "WipingStatus"  = $wmiConversionStatus.WipingStatus;
	}
	
	$wmilockStatus = $volume.GetLockStatus()
	$lockStatus = New-Object psobject -Property @{
	  "LockStatus" =  $wmilockStatus.LockStatus;
	}

	$keyProtectors = @()
	$keyProtectorReturnValue = $null
	try {
		$wmiKeyProtectors = $volume.GetKeyProtectors(0)
		$keyProtectorReturnValue = $wmiKeyProtectors.ReturnValue
		if ($keyProtectorReturnValue -eq 0) {
			foreach ($kpId in $wmiKeyProtectors.VolumeKeyProtectorID) {
				$wmiKpType = $volume.GetKeyProtectorType($kpId)
				$keyProtectors = $keyProtectors + (New-Object psobject -Property @{
				  "KeyProtectorID" = $kpId;
				  "KeyProtectorType" = $wmiKpType.KeyProtectorType;
				})
			}
		}
	} catch {
		$keyProtectorReturnValue = $null
	}

	$volumeStatus = New-Object PSObject
	Add-Member -InputObject $volumeStatus -MemberType NoteProperty -Name volume -Value $volume
	Add-Member -InputObject $volumeStatus -MemberType NoteProperty -Name version -Value $version
	Add-Member -InputObject $volumeStatus -MemberType NoteProperty -Name conversionStatus -Value $conversionStatus
	Add-Member -InputObject $volumeStatus -MemberType NoteProperty -Name lockStatus -Value $lockStatus
	Add-Member -InputObject $volumeStatus -MemberType NoteProperty -Name keyProtectors -Value $keyProtectors
	Add-Member -InputObject $volumeStatus -MemberType NoteProperty -Name keyProtectorReturnValue -Value $keyProtectorReturnValue
	$bitlockerStatus = $bitlockerStatus + $volumeStatus
}
ConvertTo-Json -Depth 3 -Compress $bitlockerStatus
`

// powershellBitlockerVolumeStatus is the struct to parse the powershell result
type powershellBitlockerVolumeStatus struct {
	Volume struct {
		ConversionStatus                 int64
		DeviceID                         string
		DriveLetter                      string
		EncryptionMethod                 int64
		IsVolumeInitializedForProtection bool
		PersistentVolumeID               string
		ProtectionStatus                 int64
		VolumeType                       int64
	}
	Version struct {
		Version int64
	}
	ConversionStatus struct {
		ConversionStatus     int64
		WipingStatus         int64
		WipingPercentage     int64
		EncryptionFlags      int64
		EncryptionPercentage int64
	}
	LockStatus struct {
		LockStatus int64
	}
	KeyProtectors psKeyProtectorList `json:"keyProtectors"`
	// KeyProtectorReturnValue is the GetKeyProtectors return code, or nil when
	// the call threw and the script could not obtain one.
	KeyProtectorReturnValue *int64 `json:"keyProtectorReturnValue"`
}

// psKeyProtector is one entry of the key protector list the collection script
// emits per volume.
type psKeyProtector struct {
	KeyProtectorID   string `json:"KeyProtectorID"`
	KeyProtectorType int64  `json:"KeyProtectorType"`
}

// psKeyProtectorList decodes the key protector list out of any of the shapes
// PowerShell produces for one. See psUnwrapList: a plain []psKeyProtector tag
// decodes the {"value":[...],"Count":n} shape to empty, which would report a
// protected volume as having no key protectors at all.
type psKeyProtectorList []psKeyProtector

func (l *psKeyProtectorList) UnmarshalJSON(data []byte) error {
	list, err := psUnwrapList(data)
	if err != nil {
		return err
	}
	if list == nil {
		*l = nil
		return nil
	}

	var out []psKeyProtector
	if err := json.Unmarshal(list, &out); err != nil {
		return err
	}
	*l = out
	return nil
}

// BitLockerVolumeStatus is the encryption state of one individual volume.
type BitLockerVolumeStatus struct {
	DeviceID           string
	DriveLetter        string
	ConversionStatus   conversionStatus
	EncryptionMethod   statusCode
	LockStatus         int64
	PersistentVolumeID string
	ProtectionStatus   statusCode
	Version            statusCode
	// KeyProtectors is empty rather than nil when the volume genuinely has
	// none. KeyProtectorError says whether an empty list can be trusted.
	KeyProtectors []BitLockerKeyProtector
	// KeyProtectorError is non-nil when the key protectors could not be read,
	// so that "none were found" is never confused with "none were readable".
	KeyProtectorError error
}

// BitLockerKeyProtector is one protector of a volume's encryption key: what
// unlocks the volume, and therefore whether the volume is bound to a TPM, a
// PIN, or a recovery password an operator holds.
type BitLockerKeyProtector struct {
	// ID is the WMI VolumeKeyProtectorID, unique among the protectors of one
	// volume.
	ID string
	// Type carries both the raw GetKeyProtectorType code and its name.
	Type statusCode
}

type conversionStatus struct {
	ConversionStatus     statusCode
	WipingStatus         statusCode
	WipingPercentage     int64
	EncryptionPercentage int64
}

type statusCode struct {
	Code int64  `json:"code"`
	Text string `json:"text"`
}

func GetBitLockerVolumes(p shared.Connection) ([]BitLockerVolumeStatus, error) {
	c, err := p.RunCommand(powershell.Encode(bitlockerStatusScript))
	if err != nil {
		return nil, err
	}
	stdout, err := io.ReadAll(c.Stdout)
	if err != nil {
		return nil, err
	}
	stderr, _ := io.ReadAll(c.Stderr)
	return bitlockerResult(stdout, c.ExitStatus, stderr)
}

// bitlockerResult turns a raw command result into volume statuses. A non-zero
// exit, or output that never arrived, is reported as an error rather than as
// an empty list: an empty list is indistinguishable from a host whose volumes
// are all unencrypted, so a failed reading would satisfy the very checks that
// are meant to catch one.
func bitlockerResult(stdout []byte, exitStatus int, stderr []byte) ([]BitLockerVolumeStatus, error) {
	if exitStatus != 0 {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = fmt.Sprintf("command exited with status %d", exitStatus)
		}
		return nil, errors.New("failed to retrieve BitLocker volumes: " + msg)
	}
	if len(bytes.TrimSpace(stdout)) == 0 {
		return nil, errors.New("failed to retrieve BitLocker volumes: the collection script produced no output")
	}
	return ParseWindowsBitlockerStatus(bytes.NewReader(stdout))
}

func ParseWindowsBitlockerStatus(r io.Reader) ([]BitLockerVolumeStatus, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	volumeStatus, err := powershell.UnmarshalList[powershellBitlockerVolumeStatus](data)
	if err != nil {
		return nil, err
	}

	res := []BitLockerVolumeStatus{}
	for i := range volumeStatus {
		v := volumeStatus[i]

		bvs := BitLockerVolumeStatus{
			DeviceID:    v.Volume.DeviceID,
			DriveLetter: v.Volume.DriveLetter,
			ConversionStatus: conversionStatus{
				ConversionStatus: statusCode{
					Code: v.ConversionStatus.ConversionStatus,
					Text: conversionStatusValues[v.ConversionStatus.ConversionStatus],
				},
				EncryptionPercentage: v.ConversionStatus.EncryptionPercentage,
				WipingStatus: statusCode{
					Code: v.ConversionStatus.WipingStatus,
					Text: wipingStatusValues[v.ConversionStatus.WipingStatus],
				},
				WipingPercentage: v.ConversionStatus.WipingPercentage,
			},
			EncryptionMethod: statusCode{
				Code: v.Volume.EncryptionMethod,
				Text: encryptionMethodValues[v.Volume.EncryptionMethod],
			},
			LockStatus:         v.LockStatus.LockStatus,
			PersistentVolumeID: v.Volume.PersistentVolumeID,
			ProtectionStatus: statusCode{
				Code: v.Volume.ProtectionStatus,
				Text: protectionStatusValues[v.Volume.ProtectionStatus],
			},
			Version: statusCode{
				Code: v.Version.Version,
				Text: fveVersionValues[v.Version.Version],
			},
			KeyProtectors:     make([]BitLockerKeyProtector, 0, len(v.KeyProtectors)),
			KeyProtectorError: KeyProtectorReadError(v.Volume.DeviceID, v.KeyProtectorReturnValue),
		}
		for j := range v.KeyProtectors {
			kp := v.KeyProtectors[j]
			bvs.KeyProtectors = append(bvs.KeyProtectors, BitLockerKeyProtector{
				ID: kp.KeyProtectorID,
				Type: statusCode{
					Code: kp.KeyProtectorType,
					Text: KeyProtectorTypeName(kp.KeyProtectorType),
				},
			})
		}
		res = append(res, bvs)
	}
	return res, nil
}
