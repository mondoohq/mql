// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"io"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

type WindowsESUStatus struct {
	SubscriptionEligible bool `json:"SubscriptionEligible"`
	LicenseActivated     bool `json:"LicenseActivated"`
}

func (e WindowsESUStatus) ESUEnabled() bool {
	return e.SubscriptionEligible || e.LicenseActivated
}

func ParseWindowsESUStatus(r io.Reader) (*WindowsESUStatus, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return &WindowsESUStatus{}, nil
	}

	var status WindowsESUStatus
	err = json.Unmarshal(data, &status)
	if err != nil {
		return nil, err
	}
	log.Debug().Interface("ESUStatus", status).Msg("parsed Windows ESU status")

	return &status, nil
}

// esuLicenseQuery finds an activated ESU license. It selects one property:
// SoftwareLicensingProduct computes some of its properties per product, so
// the same filter with every property (Get-CimInstance -ClassName -Filter)
// takes about 24 seconds on Windows 10 22H2, and this query about 1.5. The
// native path (esu_windows.go) runs the same query.
const esuLicenseQuery = "SELECT LicenseStatus FROM SoftwareLicensingProduct WHERE Name LIKE '%ESU%' AND LicenseStatus = 1"

// powershellGetWindowsESUStatus checks for Windows 10 ESU enrollment via PowerShell.
// It checks both subscription-based ESU (registry key) and MAK-activated ESU (WMI license).
func powershellGetWindowsESUStatus(conn shared.Connection) (*WindowsESUStatus, error) {
	pscommand := `
$result = @{ SubscriptionEligible = $false; LicenseActivated = $false }
$esuPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\ESU'
if (Test-Path $esuPath) {
    $props = Get-ItemProperty -Path $esuPath -ErrorAction SilentlyContinue
    if ($props.Win10CommercialW365ESUEligible -eq 1) {
        $result.SubscriptionEligible = $true
    }
}
$esuProducts = Get-CimInstance -Query "` + esuLicenseQuery + `" -ErrorAction SilentlyContinue
if ($esuProducts) { $result.LicenseActivated = $true }
$result | ConvertTo-Json -Compress
`

	log.Debug().Msg("checking Windows 10 ESU status")
	cmd, err := conn.RunCommand(powershell.Encode(pscommand))
	if err != nil {
		log.Debug().Err(err).Msg("could not run powershell command to get ESU status")
		return &WindowsESUStatus{}, nil
	}
	if cmd.ExitStatus != 0 {
		log.Debug().Int("exitCode", cmd.ExitStatus).Msg("ESU status powershell command failed")
		return &WindowsESUStatus{}, nil
	}
	return ParseWindowsESUStatus(cmd.Stdout)
}
