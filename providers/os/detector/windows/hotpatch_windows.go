// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package windows

import (
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/wmiquery"
)

// liveRegistry reads the registry of the machine the scanner runs on.
type liveRegistry struct{}

func (liveRegistry) softwareItems(path string) ([]registry.RegistryKeyItem, error) {
	return registry.GetNativeRegistryKeyItems(`HKEY_LOCAL_MACHINE\SOFTWARE\` + path)
}

func (liveRegistry) systemItems(path string) ([]registry.RegistryKeyItem, error) {
	return registry.GetNativeRegistryKeyItems(`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\` + path)
}

// nativeGetHotpatchState reads the hotpatch registry values of the local
// machine and the VBS running state from WMI. When WMI yields nothing the
// running state stays nil, like in the PowerShell path.
func nativeGetHotpatchState(arch string) *HotpatchState {
	st := readHotpatchRegistry(liveRegistry{}, arch)

	rows, err := wmiquery.QueryNamespace(`root\Microsoft\Windows\DeviceGuard`,
		"SELECT VirtualizationBasedSecurityStatus FROM Win32_DeviceGuard", "VirtualizationBasedSecurityStatus")
	if err != nil || len(rows) == 0 {
		log.Debug().Err(err).Msg("could not query Win32_DeviceGuard, the VBS running state is unknown")
	} else if status, ok := rows[0].Int64("VirtualizationBasedSecurityStatus"); ok {
		st.VirtualizationBasedSecurityStatus = &status
	} else {
		log.Debug().Msg("Win32_DeviceGuard returned no VBS status")
	}

	log.Debug().Interface("hotpatch", st).Msg("read windows hotpatch state")
	return st
}
