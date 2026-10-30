// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package runningbinaries

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// nativeWindowsInstallerOwners reads the Windows Installer component
// registry (see windowsInstallerKey) for the products that installed paths.
// ok is false when the registry cannot be read, and the caller asks
// PowerShell instead.
func nativeWindowsInstallerOwners(paths []string) (map[string]string, bool) {
	res := map[string]string{}
	want := make(map[string]bool, len(paths))
	for _, p := range paths {
		want[WindowsPathKey(p)] = true
	}

	ud, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsInstallerKey, registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		// no product was ever installed with Windows Installer
		return res, true
	}
	if err != nil {
		return nil, false
	}
	defer ud.Close()

	sids, err := ud.ReadSubKeyNames(-1)
	if err != nil {
		return nil, false
	}
	for _, sid := range sids {
		comps, err := registry.OpenKey(ud, sid+`\Components`, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		components, _ := comps.ReadSubKeyNames(-1)
		for _, c := range components {
			k, err := registry.OpenKey(comps, c, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			products, _ := k.ReadValueNames(-1)
			for _, product := range products {
				path, _, err := k.GetStringValue(product)
				if err != nil || !want[WindowsPathKey(path)] {
					continue
				}
				addInstallerOwner(res, path, installerProductName(ud, sid, product))
			}
			k.Close()
		}
		comps.Close()
	}
	return res, true
}

// installerProductName reads a product's name from its install properties.
func installerProductName(ud registry.Key, sid, product string) string {
	k, err := registry.OpenKey(ud, sid+`\Products\`+product+`\InstallProperties`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	name, _, _ := k.GetStringValue("DisplayName")
	return name
}
