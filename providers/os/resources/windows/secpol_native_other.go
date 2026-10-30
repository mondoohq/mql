// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package windows

import "errors"

// NativeSecpolExport is only available on Windows; the caller checks the
// connection first (shared.WindowsNative).
func NativeSecpolExport() (string, error) {
	return "", errors.New("the native security policy is only available on Windows")
}
