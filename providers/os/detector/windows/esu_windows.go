// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/wmiquery"
	"golang.org/x/sys/windows/registry"
)

func GetWindowsESUStatus(conn shared.Connection) (*WindowsESUStatus, error) {
	log.Debug().Msg("checking Windows 10 ESU status")

	// if we are running locally on windows, check registry and WMI directly
	if conn.Type() == shared.Type_Local {
		status := &WindowsESUStatus{}

		// Check subscription-based ESU via registry
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\ESU`, registry.QUERY_VALUE)
		if err == nil {
			defer k.Close()

			eligible, _, err := k.GetIntegerValue("Win10CommercialW365ESUEligible")
			if err != nil && err != registry.ErrNotExist {
				log.Debug().Err(err).Msg("could not get Win10CommercialW365ESUEligible value")
			}
			status.SubscriptionEligible = eligible == 1
		} else {
			log.Debug().Err(err).Msg("could not open ESU registry key, subscription ESU may not be configured")
		}

		// Check MAK-activated ESU via WMI. A failed WMI query (or a panic in
		// WMI) must not read as "no ESU license": fall back to PowerShell,
		// which reports both values.
		products, err := wmiquery.Query(esuLicenseQuery, "LicenseStatus")
		if err != nil {
			log.Debug().Err(err).Msg("could not query WMI for ESU license status, falling back to PowerShell")
			return powershellGetWindowsESUStatus(conn)
		}
		status.LicenseActivated = len(products) > 0

		return status, nil
	}

	// for all non-local checks use powershell
	return powershellGetWindowsESUStatus(conn)
}
