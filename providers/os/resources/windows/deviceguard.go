// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// PSGetDeviceGuard reads the running Device Guard state from the
// Win32_DeviceGuard WMI class, which reports what Virtualization-Based
// Security actually negotiated at boot rather than what policy asked for.
//
// The class exists on Windows 10, Windows 11, and Windows Server 2016 and
// later, and reading it needs an elevated session. Both failures are reported
// as a non-zero exit rather than as an empty result: an empty result would
// read as "no security services are running" on a host where they are.
const PSGetDeviceGuard = `
$ErrorActionPreference = 'Stop'
try {
  $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 1
}
if ($null -eq $dg) {
  [Console]::Error.WriteLine("Win32_DeviceGuard returned no instance")
  exit 1
}
[PSCustomObject]@{
  AvailableSecurityProperties = $dg.AvailableSecurityProperties
  SecurityServicesConfigured = $dg.SecurityServicesConfigured
  SecurityServicesRunning = $dg.SecurityServicesRunning
  CodeIntegrityPolicyEnforcementStatus = $dg.CodeIntegrityPolicyEnforcementStatus
  UsermodeCodeIntegrityPolicyEnforcementStatus = $dg.UsermodeCodeIntegrityPolicyEnforcementStatus
  VirtualizationBasedSecurityStatus = $dg.VirtualizationBasedSecurityStatus
} | ConvertTo-Json -Depth 3 -Compress
`

// DeviceGuardStatus is the parsed result of PSGetDeviceGuard.
//
// Every value is nullable. A nil list or pointer means Win32_DeviceGuard did
// not report the property (an older build, for instance), which the resource
// surfaces as null so it stays distinguishable from an explicit 0 or from an
// empty list. The raw codes are carried through unchanged; the meanings are
// documented on the resource fields.
type DeviceGuardStatus struct {
	AvailableSecurityProperties                  PSInt64Array `json:"AvailableSecurityProperties"`
	SecurityServicesConfigured                   PSInt64Array `json:"SecurityServicesConfigured"`
	SecurityServicesRunning                      PSInt64Array `json:"SecurityServicesRunning"`
	CodeIntegrityPolicyEnforcementStatus         *int64       `json:"CodeIntegrityPolicyEnforcementStatus"`
	UsermodeCodeIntegrityPolicyEnforcementStatus *int64       `json:"UsermodeCodeIntegrityPolicyEnforcementStatus"`
	VirtualizationBasedSecurityStatus            *int64       `json:"VirtualizationBasedSecurityStatus"`
}

// ParseDeviceGuardStatus decodes the JSON emitted by PSGetDeviceGuard. Empty
// output is an error rather than an all-null result: the script exits non-zero
// on every failure it can detect, so output that is missing anyway means the
// reading cannot be trusted.
func ParseDeviceGuardStatus(r io.Reader) (*DeviceGuardStatus, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(string(data)) == "" {
		return nil, errors.New("Win32_DeviceGuard returned no data")
	}

	var status DeviceGuardStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, err
	}
	return &status, nil
}
