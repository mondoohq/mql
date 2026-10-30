// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package selfupdate

import (
	"runtime"
	"unsafe"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// upgradeCodes are the UpgradeCode GUIDs of the Mondoo MSI packages.
//
// An UpgradeCode is the one identifier Windows Installer guarantees is stable
// across every version of a product -- that is what it is for, and it is how a
// package recognises its own earlier versions in order to upgrade them. A
// ProductCode is not: the Mondoo WiX Product carries Id="*", so a fresh one is
// generated on every build and cannot be compiled in.
//
// There is one UpgradeCode per SKU and per architecture, and a machine has at
// most one of them installed. They are listed here in the order they are most
// likely to be found.
//
// Kept in sync by hand with the installer's WiX sources. A new SKU needs a new
// entry here, which is the cost of this fallback; the pointer key below is
// what avoids that cost on installs new enough to have it.
var upgradeCodes = []string{
	"{B0FEE933-CCD2-467C-8FE4-BB0AC6A099C8}", // standard, x64
	"{090CFB7D-C00C-4D36-94FE-F649A4B29C91}", // standard, arm64
	"{4ABDD5C7-E1E1-41A6-8119-DCE65634A6CC}", // enterprise
}

// displayNameValue identifies the Add/Remove entry. The fallback path resolves
// a ProductCode by inference rather than being handed one, so the entry is
// checked before anything is written to it.
const displayNameValue = "DisplayName"

// mondooDisplayNames are the DisplayName values the MSI registers, one per
// SKU. They are the WiX ProductName verbatim, and are matched exactly rather
// than by prefix: "Mondoo" is short enough that a prefix test would accept an
// unrelated product that happens to start with it.
var mondooDisplayNames = map[string]bool{
	"Mondoo":            true, // standard
	"Mondoo Enterprise": true, // enterprise
}

var (
	modmsi                      = windows.NewLazySystemDLL("msi.dll")
	procMsiEnumRelatedProductsW = modmsi.NewProc("MsiEnumRelatedProductsW")
)

// Return codes from MsiEnumRelatedProducts that are ordinary answers rather
// than faults. Anything else is reported.
const (
	errorSuccess        = 0
	errorNoMoreItems    = 259
	errorUnknownProduct = 1605
	errorBadConfig      = 1610
)

// productCodeGUIDLen is the length of a GUID in registry format,
// {8-4-4-4-12}, plus the terminating NUL. MsiEnumRelatedProducts requires a
// buffer of at least this size and does not report the length it needs.
const productCodeGUIDLen = 39

// relatedProductCode asks Windows Installer which product is installed under
// upgradeCode, returning "" when none is.
//
// This is the same lookup an MSI performs against its own Upgrade table, and
// the same one Chrome's updater uses to find the package it belongs to. Only
// the first related product is read: a machine carries at most one Mondoo SKU,
// and a second would be a broken install rather than a case to choose between.
func relatedProductCode(upgradeCode string) (string, error) {
	code, err := windows.UTF16PtrFromString(upgradeCode)
	if err != nil {
		return "", errors.Wrapf(err, "cannot encode upgrade code %s", upgradeCode)
	}

	buf := make([]uint16, productCodeGUIDLen)

	// The two unsafe.Pointer conversions below are case 4 of the patterns
	// documented in the unsafe package: "Conversion of a Pointer to a uintptr
	// when calling syscall.Syscall". Both conversions are written inside the
	// call expression itself, which is what makes them valid -- the compiler
	// and garbage collector recognise that form and keep the referents alive
	// and unmoved for the duration of the call. Assigning either uintptr to a
	// variable first would break that guarantee, so they must stay inline.
	//
	// This is the same shape every wrapper in golang.org/x/sys/windows uses;
	// there is no pointer-free way to hand a DLL a string and a buffer.
	ret, _, _ := procMsiEnumRelatedProductsW.Call(
		uintptr(unsafe.Pointer(code)),
		0, // dwReserved, must be 0
		0, // iProductIndex, the first related product
		uintptr(unsafe.Pointer(&buf[0])),
	)

	// Case 4 already keeps these alive across the call. Said explicitly so
	// that a later edit moving either conversion out of the call expression
	// does not quietly become a use-after-free.
	runtime.KeepAlive(code)
	runtime.KeepAlive(buf)

	switch ret {
	case errorSuccess:
		return windows.UTF16ToString(buf), nil
	case errorNoMoreItems, errorUnknownProduct:
		// Nothing installed under this UpgradeCode. The expected answer for
		// every SKU the machine does not have.
		return "", nil
	case errorBadConfig:
		return "", errors.Errorf("registration for upgrade code %s is corrupt", upgradeCode)
	default:
		return "", errors.Errorf("MsiEnumRelatedProducts(%s) returned %d", upgradeCode, ret)
	}
}

// productCodeFromUpgradeCodes resolves the installed ProductCode without the
// MSI having recorded one, by asking Windows Installer about each known
// UpgradeCode in turn. Returns "" when no Mondoo package is installed.
func productCodeFromUpgradeCodes() (string, error) {
	for _, upgradeCode := range upgradeCodes {
		productCode, err := relatedProductCode(upgradeCode)
		if err != nil {
			// One corrupt or unreadable registration should not hide a healthy
			// one behind it in the list.
			log.Debug().Err(err).Str("upgrade_code", upgradeCode).
				Msg("cannot resolve product code, trying the next upgrade code")
			continue
		}
		if productCode == "" {
			continue
		}

		// The pointer key is written by the installer and names the package
		// exactly. This path infers it instead, so confirm the entry really is
		// the Mondoo package before it is treated as one.
		if !isMondooUninstallEntry(productCode) {
			log.Debug().Str("product_code", productCode).Str("upgrade_code", upgradeCode).
				Msg("related product is not a Mondoo Add/Remove entry, ignoring it")
			continue
		}
		return productCode, nil
	}
	return "", nil
}

// isMondooUninstallEntry reports whether the Add/Remove entry for productCode
// exists and belongs to Mondoo.
func isMondooUninstallEntry(productCode string) bool {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		uninstallKey+`\`+productCode,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return false
	}
	defer k.Close()

	name, _, err := k.GetStringValue(displayNameValue)
	if err != nil {
		return false
	}
	return mondooDisplayNames[name]
}
