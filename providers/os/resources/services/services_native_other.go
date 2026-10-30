// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package services

import "errors"

// listNativeWindowsServices is only available when mql itself runs on
// Windows. WindowsServiceManager checks that before calling it.
func listNativeWindowsServices() ([]*Service, error) {
	return nil, errors.New("the Windows Service Control Manager can only be queried on Windows")
}
