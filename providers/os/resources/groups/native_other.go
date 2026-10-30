// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package groups

import "errors"

// nativeWindowsLocalGroups is only available on Windows; shared.WindowsNative
// never selects it elsewhere.
func nativeWindowsLocalGroups() ([]WindowsLocalGroup, error) {
	return nil, errors.New("native Windows groups are only available on Windows")
}
