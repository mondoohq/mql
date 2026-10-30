// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// PSGetTpm collects Trusted Platform Module state. Get-Tpm provides the
// presence/readiness flags, the manufacturer, the dictionary-attack lockout
// state and the automatic provisioning mode, while the Win32_Tpm WMI class
// provides the specification version.
//
// A failure to read either source exits non-zero instead of reporting an
// absent TPM. With errors suppressed and every flag cast with [bool], a
// Get-Tpm that could not answer (a session that is not elevated, the TBS
// service stopped) read as present=false ready=false, the same answer a
// machine with no TPM gives. The one Get-Tpm failure that is an answer is the
// one on a machine with no TPM at all: Server 2016 throws there instead of
// returning TpmPresent=False. Win32_Tpm tells the two apart, since it has an
// instance exactly when a TPM device exists.
//
// The owner authorization value that Get-Tpm also carries is deliberately not
// collected. It is the secret that authorizes clearing and taking ownership of
// the TPM, and nothing here needs it.
const PSGetTpm = `
$ErrorActionPreference = 'Stop'
try {
  $wmi = @(Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm)
} catch {
  [Console]::Error.WriteLine("could not read Win32_Tpm: " + $_.Exception.Message)
  exit 1
}
try {
  $tpm = Get-Tpm
} catch {
  if ($wmi.Count -gt 0) {
    [Console]::Error.WriteLine("Get-Tpm failed on a host that has a TPM: " + $_.Exception.Message)
    exit 1
  }
  $tpm = $null
}
$spec = if ($wmi.Count -gt 0) { $wmi[0].SpecVersion } else { $null }
[PSCustomObject]@{
  TpmPresent          = [bool]$tpm.TpmPresent
  TpmReady            = [bool]$tpm.TpmReady
  TpmEnabled          = [bool]$tpm.TpmEnabled
  TpmActivated        = [bool]$tpm.TpmActivated
  ManufacturerVersion = [string]$tpm.ManufacturerVersion
  ManufacturerId      = $(if($null -eq $tpm.ManufacturerId){0}else{[int64]$tpm.ManufacturerId})
  ManufacturerIdTxt   = [string]$tpm.ManufacturerIdTxt
  LockedOut           = [bool]$tpm.LockedOut
  LockoutCount        = $(if($null -eq $tpm.LockoutCount){0}else{[int64]$tpm.LockoutCount})
  LockoutHealTime     = [string]$tpm.LockoutHealTime
  AutoProvisioning    = [string]$tpm.AutoProvisioning
  OwnerClearDisabled  = [bool]$tpm.OwnerClearDisabled
  SpecVersion         = [string]$spec
} | ConvertTo-Json
`

// TpmInfo is the parsed result of PSGetTpm. ParseTpm trims the NUL padding
// Get-Tpm leaves on its fixed-width strings, so every string field holds the
// value as Win32_Tpm reports it.
type TpmInfo struct {
	TpmPresent   bool `json:"TpmPresent"`
	TpmReady     bool `json:"TpmReady"`
	TpmEnabled   bool `json:"TpmEnabled"`
	TpmActivated bool `json:"TpmActivated"`
	// ManufacturerVersion is the firmware version of the TPM, for example
	// "8224.786.18.4".
	ManufacturerVersion string `json:"ManufacturerVersion"`
	// ManufacturerId is the raw TCG vendor identifier, usually four ASCII
	// characters packed into an integer.
	ManufacturerId int64 `json:"ManufacturerId"`
	// ManufacturerIdTxt is the readable form of the vendor identifier.
	ManufacturerIdTxt string `json:"ManufacturerIdTxt"`
	// LockedOut is true while the TPM is refusing owner authorization after
	// too many failed attempts.
	LockedOut bool `json:"LockedOut"`
	// LockoutCount is the number of authorization failures counted against
	// the lockout threshold.
	LockoutCount int64 `json:"LockoutCount"`
	// LockoutHealTime is how long it takes the TPM to forget one failure,
	// reported as a human-readable duration such as "2 hours".
	LockoutHealTime string `json:"LockoutHealTime"`
	// AutoProvisioning is Enabled, Disabled, or EnabledForCertainOnly.
	AutoProvisioning string `json:"AutoProvisioning"`
	// OwnerClearDisabled is true when the TPM cannot be cleared from the
	// operating system.
	OwnerClearDisabled bool `json:"OwnerClearDisabled"`
	// SpecVersion is the raw Win32_Tpm value, e.g. "2.0, 0, 1.59".
	SpecVersion string `json:"SpecVersion"`
}

// Manufacturer returns the readable vendor identifier with the padding the
// firmware adds removed. Get-Tpm renders the fixed-width field verbatim, so an
// untrimmed value compares unequal to the vendor name it obviously is.
func (t *TpmInfo) Manufacturer() string {
	return trimTpmString(t.ManufacturerIdTxt)
}

// MajorSpecVersion returns just the major specification version (e.g. "2.0")
// from the raw, comma-separated Win32_Tpm SpecVersion value.
func (t *TpmInfo) MajorSpecVersion() string {
	major, _, _ := strings.Cut(t.SpecVersion, ",")
	return strings.TrimSpace(major)
}

// trimTpmString removes the NUL padding and surrounding whitespace Get-Tpm
// leaves on the fixed-width strings it reads from the firmware. A version
// such as "8224.786.18.4" arrives followed by 19 NUL bytes, which no string
// comparison or version check expects. NULs are trimmed from both ends: a
// NUL is never part of a readable firmware string, wherever it sits.
func trimTpmString(s string) string {
	return strings.TrimSpace(strings.Trim(s, "\x00"))
}

// ParseTpm decodes the JSON emitted by PSGetTpm. The script emits an object on
// every successful run, including on a machine without a TPM, so empty output
// means it never ran and is an error rather than an absent TPM.
func ParseTpm(r io.Reader) (*TpmInfo, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, errors.New("failed to retrieve TPM information: the collection script produced no output")
	}

	var info TpmInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	info.ManufacturerVersion = trimTpmString(info.ManufacturerVersion)
	info.ManufacturerIdTxt = trimTpmString(info.ManufacturerIdTxt)
	info.LockoutHealTime = trimTpmString(info.LockoutHealTime)
	info.AutoProvisioning = trimTpmString(info.AutoProvisioning)
	info.SpecVersion = trimTpmString(info.SpecVersion)
	return &info, nil
}
