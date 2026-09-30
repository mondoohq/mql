// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package services

import "errors"

// nativeWindowsServices is never reached off Windows: shared.WindowsNative
// requires a local connection on Windows.
func nativeWindowsServices() ([]*Service, error) {
	return nil, errors.New("native Windows services are only available on Windows")
}
