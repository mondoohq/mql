// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

type IntuneDeviceInfo struct {
	EnrollmentGUID string `json:"EnrollmentGUID"`
	EntDMID        string `json:"EntDMID"`
	// Certs holds the base64 DER of the device certificates that may carry
	// the device's Microsoft identity. PowerShell emits a single string instead
	// of an array when there is exactly one, so both shapes are accepted.
	Certs json.RawMessage `json:"Certs,omitempty"`
}

// IntuneInfo is what the Windows detector learns about a device's Microsoft
// enrollment: the Intune device ID from the enrollment registry, and the public
// device certificates of the local machine's personal store.
type IntuneInfo struct {
	EntDMID      string
	Certificates [][]byte
}

// Identity derives the device's Microsoft identity from its certificates.
func (i *IntuneInfo) Identity() DeviceIdentity {
	if i == nil {
		return DeviceIdentity{}
	}
	return ParseDeviceCertificates(i.Certificates, i.EntDMID)
}

func ParseIntuneDeviceID(r io.Reader) (string, error) {
	info, err := ParseIntuneInfo(r)
	if err != nil || info == nil {
		return "", err
	}
	return info.EntDMID, nil
}

// ParseIntuneInfo parses the output of the enrollment and certificate query.
// Empty output means the device is neither Intune-enrolled nor Entra-joined.
func ParseIntuneInfo(r io.Reader) (*IntuneInfo, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}

	var raw IntuneDeviceInfo
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	log.Debug().Str("EntDMID", raw.EntDMID).Msg("parsed Intune device information")

	info := &IntuneInfo{EntDMID: raw.EntDMID}
	for _, b64 := range certStrings(raw.Certs) {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			log.Debug().Err(err).Msg("skipping undecodable device certificate")
			continue
		}
		info.Certificates = append(info.Certificates, der)
	}
	return info, nil
}

func certStrings(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil && one != "" {
		return []string{one}
	}
	return nil
}

// intuneInfoScript reads the Intune enrollment ID from the registry and the
// public device certificates from the local machine's personal store. Only the
// certificates' public DER is emitted; private keys are never touched. The
// issuer filter here is a coarse pre-filter; the exact match happens in Go.
const intuneInfoScript = `$e = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Enrollments\' -ErrorAction SilentlyContinue | ForEach-Object { $dmClient = Join-Path $_.PSPath 'DMClient\MS DM Server'; if (Test-Path $dmClient) { $props = Get-ItemProperty $dmClient -ErrorAction SilentlyContinue; if ($props.EntDMID) { [PSCustomObject]@{ EnrollmentGUID = $_.PSChildName; EntDMID = $props.EntDMID } } } } | Select-Object -First 1
$c = @(Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue | Where-Object { $_.Issuer -like '*Microsoft Intune MDM Device CA*' -or $_.Issuer -like '*MS-Organization-Access*' } | ForEach-Object { [Convert]::ToBase64String($_.RawData) })
if ($e -or $c.Count -gt 0) { [PSCustomObject]@{ EnrollmentGUID = $e.EnrollmentGUID; EntDMID = $e.EntDMID; Certs = $c } | ConvertTo-Json -Compress }`

// IntuneInfoCommand returns the encoded PowerShell command that reads the
// Intune enrollment ID and the device certificates.
func IntuneInfoCommand() string {
	return powershell.Encode(intuneInfoScript)
}

// powershellGetIntuneInfo runs one PowerShell command that returns the Intune
// enrollment ID and the device certificates.
func powershellGetIntuneInfo(conn shared.Connection) (*IntuneInfo, error) {
	log.Debug().Msg("checking Intune device ID and device certificates")
	cmd, err := conn.RunCommand(IntuneInfoCommand())
	if err != nil {
		log.Debug().Err(err).Msg("could not run powershell command to get Intune device information")
		return nil, nil
	}
	return ParseIntuneInfo(cmd.Stdout)
}

// GetIntuneDeviceID returns the Intune device ID from the enrollment registry.
func GetIntuneDeviceID(conn shared.Connection) (string, error) {
	info, err := GetIntuneInfo(conn)
	if err != nil || info == nil {
		return "", err
	}
	return info.EntDMID, nil
}
