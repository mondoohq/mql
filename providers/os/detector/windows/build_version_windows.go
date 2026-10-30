// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package windows

import (
	"runtime"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"golang.org/x/sys/windows/registry"
)

func GetWindowsOSBuild(conn shared.Connection) (*WindowsCurrentVersion, error) {
	// if we are running locally on windows, we want to avoid using powershell to be faster
	if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
		if err != nil {
			return nil, err
		}
		defer k.Close()

		currentBuild, _, err := k.GetStringValue("CurrentBuild")
		if err != nil && err != registry.ErrNotExist {
			return nil, err
		}

		ubr, _, err := k.GetIntegerValue("UBR")
		if err != nil && err != registry.ErrNotExist {
			return nil, err
		}

		edition, _, err := k.GetStringValue("EditionID")
		if err != nil && err != registry.ErrNotExist {
			return nil, err
		}

		displayVersion, _, err := k.GetStringValue("DisplayVersion")
		if err != nil && err != registry.ErrNotExist {
			return nil, err
		}

		title, _, err := k.GetStringValue("ProductName")
		if err != nil && err != registry.ErrNotExist {
			return nil, err
		}

		installationType, _, err := k.GetStringValue("InstallationType")
		if err != nil && err != registry.ErrNotExist {
			return nil, err
		}

		systemKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\ProductOptions`, registry.QUERY_VALUE)
		if err != nil {
			return nil, err
		}
		defer systemKey.Close()

		productType, _, err := systemKey.GetStringValue("ProductType")
		if err != nil && err != registry.ErrNotExist {
			return nil, err
		}

		envKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, registry.QUERY_VALUE)
		if err != nil {
			return nil, err
		}
		defer envKey.Close()

		arch, _, err := envKey.GetStringValue("PROCESSOR_ARCHITECTURE")
		if err != nil && err != registry.ErrNotExist {
			return nil, err
		}

		return &WindowsCurrentVersion{
			CurrentBuild:     currentBuild,
			EditionID:        edition,
			UBR:              int(ubr),
			Architecture:     arch,
			DisplayVersion:   displayVersion,
			ProductName:      title,
			ProductType:      productType,
			InstallationType: installationType,
		}, nil
	}

	// for all non-local checks use powershell
	return powershellGetWindowsOSBuild(conn)
}
