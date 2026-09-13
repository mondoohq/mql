// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package selfupdate

import (
	"github.com/cockroachdb/errors"
	"golang.org/x/sys/windows/registry"
)

const (
	// mondooInstallKey is written by the MSI. It exists so a self-updating
	// binary can find the package that installed it without compiling in any
	// GUID: the ProductCode is regenerated on every build (the WiX Product
	// carries Id="*"), so it is not knowable ahead of time, and the
	// UpgradeCode differs per SKU and per architecture. The installer knows
	// both; the binary should not have to.
	mondooInstallKey = `SOFTWARE\Mondoo`

	// productCodeValue names the installed package's ProductCode, which is the
	// subkey under Uninstall that Windows keeps its Add/Remove entry in.
	productCodeValue = "ProductCode"

	uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

	// displayVersionValue is what Add/Remove Programs shows, and what
	// inventory tooling reads -- including this project's own Windows package
	// resource, which enumerates these keys and reports DisplayVersion.
	displayVersionValue = "DisplayVersion"
)

// updateRegisteredVersion points the installed package's Add/Remove entry at
// the version now on disk.
//
// Windows Installer derives DisplayVersion from the MSI's ProductVersion at
// install time and never revisits it. Since the binary updates itself
// underneath the package, that value goes stale the moment an update lands,
// and Windows keeps reporting whatever shipped in the MSI. Chrome has the same
// shape and resolves it the same way: the package is a delivery vehicle, and
// the version it reports is derived from the binary rather than the installer.
//
// Not an error when there is nothing to update. A tarball, Chocolatey or
// container install has no MSI behind it and so no Add/Remove entry to
// correct; that is an ordinary state, not a failure.
func updateRegisteredVersion(version string) error {
	if version == "" {
		return errors.New("refusing to register an empty version")
	}

	productCode, err := installedProductCode()
	if err != nil {
		return err
	}
	if productCode == "" {
		// Not an MSI install.
		return nil
	}

	// WOW64_64KEY explicitly: the MSI is a 64-bit package and registers under
	// the 64-bit view. A 64-bit process gets that view by default, but saying
	// so keeps this correct if the binary is ever built for 386.
	//
	// Read before write, and skip the write when it already agrees. This is
	// called on every update check, not only when an update lands, so the
	// common case is that there is nothing to do -- and it keeps a
	// non-elevated process from failing on a SET_VALUE open it did not need.
	path := uninstallKey + `\` + productCode

	if current, err := registeredDisplayVersion(path); err == nil && current == version {
		return nil
	}

	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		path,
		registry.SET_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return errors.Wrapf(err, "cannot open the Add/Remove entry for %s", productCode)
	}
	defer k.Close()

	if err := k.SetStringValue(displayVersionValue, version); err != nil {
		return errors.Wrapf(err, "cannot set %s", displayVersionValue)
	}
	return nil
}

// registeredDisplayVersion reads what the Add/Remove entry currently reports.
func registeredDisplayVersion(path string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()

	v, _, err := k.GetStringValue(displayVersionValue)
	return v, err
}

// installedProductCode reads the ProductCode the MSI recorded, or "" when
// there is no MSI install on this machine.
func installedProductCode() (string, error) {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		mondooInstallKey,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", nil
		}
		return "", errors.Wrapf(err, "cannot read %s", mondooInstallKey)
	}
	defer k.Close()

	productCode, _, err := k.GetStringValue(productCodeValue)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", nil
		}
		return "", errors.Wrapf(err, "cannot read %s\\%s", mondooInstallKey, productCodeValue)
	}
	return productCode, nil
}
