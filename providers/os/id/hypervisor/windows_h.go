// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hypervisor

import (
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/smbios"
)

// Model + manufacturer from Win32_ComputerSystem, SMBIOS version from Win32_BIOS.
const windowsDetectionCommand = `$cs = Get-CimInstance -ClassName Win32_ComputerSystem; ` +
	`$bios = Get-CimInstance -ClassName Win32_BIOS; ` +
	`"$($cs.Model)|$($cs.Manufacturer)|$($bios.SMBIOSBIOSVersion)"`

// detectWindowsHypervisor detects the hypervisor on Windows.
func (h *hyper) detectWindowsHypervisor() (string, bool) {
	// With MONDOO_WINDOWS_NATIVE on a local connection, the three values come
	// from the SMBIOS data the provider has already read natively and memoized
	// for this connection, instead of a PowerShell process of their own.
	if shared.WindowsNative(h.connection) {
		if info, ok := h.windowsSmbiosDetectionInfo(); ok {
			return mapHypervisor(info)
		}
	}

	stdout, err := h.RunCommand(windowsDetectionCommand)
	if err != nil {
		log.Debug().Err(err).Msg("could not detect hypervisor")
		return "", false
	}
	return mapHypervisor(stdout)
}

// windowsSmbiosDetectionInfo builds the same "model|manufacturer|bios version"
// string as windowsDetectionCommand from the connection's SMBIOS data. Both read
// SMBIOS: Win32_ComputerSystem's Model and Manufacturer are the system product
// name and manufacturer of SMBIOS type 1, which the SMBIOS manager reads from
// Win32_ComputerSystemProduct (Name, Vendor); the BIOS version is
// Win32_BIOS.SMBIOSBIOSVersion in both.
func (h *hyper) windowsSmbiosDetectionInfo() (string, bool) {
	mgr, err := smbios.ResolveManager(h.connection, h.platform)
	if err != nil {
		log.Debug().Err(err).Msg("could not resolve the smbios manager for hypervisor detection")
		return "", false
	}
	info, err := mgr.Info()
	if err != nil || info == nil {
		log.Debug().Err(err).Msg("could not read smbios for hypervisor detection")
		return "", false
	}
	return windowsDetectionInfo(info), true
}

// windowsDetectionInfo is the input mapHypervisor gets from
// windowsDetectionCommand, built from SMBIOS data.
func windowsDetectionInfo(info *smbios.SmBiosInfo) string {
	return info.SysInfo.Model + "|" + info.SysInfo.Vendor + "|" + info.BIOS.Version
}
