// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package windows

import (
	"errors"
	"runtime"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/wmiquery"
	"golang.org/x/sys/windows/registry"
)

func GetWindowsHotpatch(conn shared.Connection, pf *inventory.Platform) (bool, error) {
	log.Debug().Msg("checking windows hotpatch")

	if !hotpatchSupported(pf) {
		return false, nil
	}

	// if we are running locally on windows, we want to avoid using powershell to be faster
	if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
		if isClientOS(pf) {
			return nativeGetWindowsClientHotpatch()
		}
		return nativeGetWindowsServerHotpatch(pf.Arch)
	}

	// for all non-local checks use powershell
	return powershellGetWindowsHotpatch(conn, pf)
}

// nativeGetWindowsClientHotpatch reads AllowRebootlessUpdates and the configured
// VBS value from the Windows registry and the VBS running state from WMI. When
// the WMI state is unavailable the running state stays empty and the registry
// value decides, like in the PowerShell path.
func nativeGetWindowsClientHotpatch() (bool, error) {
	updateKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\PolicyManager\current\device\Update`, registry.QUERY_VALUE)
	if err != nil {
		log.Debug().Err(err).Msg("could not open registry key PolicyManager Update")
		return false, nil
	}
	defer updateKey.Close()

	allowRebootless, _, err := updateKey.GetIntegerValue("AllowRebootlessUpdates")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		log.Debug().Err(err).Msg("could not get AllowRebootlessUpdates value")
		return false, err
	}

	hp := WindowsClientHotpatch{AllowRebootlessUpdates: strconv.FormatUint(allowRebootless, 10)}

	// The DeviceGuard key may be absent while VBS is running, so a missing key
	// or value is not fatal: the WMI running state is authoritative.
	if systemKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\DeviceGuard`, registry.QUERY_VALUE); err != nil {
		log.Debug().Err(err).Msg("could not open registry key DeviceGuard")
	} else {
		enableVBS, _, err := systemKey.GetIntegerValue("EnableVirtualizationBasedSecurity")
		systemKey.Close()
		if err == nil {
			hp.EnableVirtualizationBasedSecurity = strconv.FormatUint(enableVBS, 10)
		} else if !errors.Is(err, registry.ErrNotExist) {
			log.Debug().Err(err).Msg("could not get EnableVirtualizationBasedSecurity value")
		}
	}

	rows, err := wmiquery.QueryNamespace(`root\Microsoft\Windows\DeviceGuard`,
		"SELECT VirtualizationBasedSecurityStatus FROM Win32_DeviceGuard", "VirtualizationBasedSecurityStatus")
	if err != nil || len(rows) == 0 {
		log.Debug().Err(err).Msg("could not query Win32_DeviceGuard, falling back to the registry VBS value")
	} else if status, ok := rows[0].Int64("VirtualizationBasedSecurityStatus"); ok {
		hp.VirtualizationBasedSecurityStatus = strconv.FormatInt(status, 10)
	} else {
		log.Debug().Msg("Win32_DeviceGuard returned no VBS status, falling back to the registry VBS value")
	}

	log.Debug().Interface("ClientHotpatch", hp).Msg("parsed windows client hotpatch settings")
	return hp.enabled(), nil
}

// nativeGetWindowsServerHotpatch reads hotpatch enrollment, VBS, and HotPatchTableSize directly from the Windows registry.
func nativeGetWindowsServerHotpatch(arch string) (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Update\TargetingInfo\DynamicInstalled\Hotpatch.`+strings.ToLower(arch), registry.QUERY_VALUE)
	if err != nil {
		log.Debug().Err(err).Msg("could not open registry key DynamicInstalled")
		return false, nil
	}
	defer k.Close()

	hotpatchName, _, err := k.GetStringValue("Name")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return false, err
	}

	systemKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\DeviceGuard`, registry.QUERY_VALUE)
	if err != nil {
		log.Debug().Err(err).Msg("could not open registry key DeviceGuard")
		return false, nil
	}
	defer systemKey.Close()

	enableVirtualizationBasedSecurity, _, err := systemKey.GetIntegerValue("EnableVirtualizationBasedSecurity")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		log.Debug().Err(err).Msg("could not get EnableVirtualizationBasedSecurity value")
		return false, err
	}

	memoryKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`, registry.QUERY_VALUE)
	if err != nil {
		log.Debug().Err(err).Msg("could not open registry key Memory Management")
		return false, nil
	}
	defer memoryKey.Close()

	hotPatchTableSize, _, err := memoryKey.GetIntegerValue("HotPatchTableSize")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		log.Debug().Err(err).Msg("could not get HotPatchTableSize value")
		return false, err
	}

	log.Debug().Str("hotpatchName", hotpatchName).Int("enableVirtualizationBasedSecurity", int(enableVirtualizationBasedSecurity)).Int("hotPatchTableSize", int(hotPatchTableSize)).Msg("parsed windows server hotpatch settings")

	return hotpatchName == HotpatchPackage && enableVirtualizationBasedSecurity == 1 && hotPatchTableSize > 0, nil
}
