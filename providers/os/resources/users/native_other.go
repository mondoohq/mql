// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package users

import "errors"

// nativeWindowsLocalUsers is only available on Windows; shared.WindowsNative
// never selects it elsewhere.
func nativeWindowsLocalUsers() ([]WindowsLocalUser, error) {
	return nil, errors.New("native Windows users are only available on Windows")
}
