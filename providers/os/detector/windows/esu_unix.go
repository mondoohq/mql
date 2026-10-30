// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package windows

import "go.mondoo.com/mql/providers/os/connection/shared"

func GetWindowsESUStatus(conn shared.Connection) (*WindowsESUStatus, error) {
	return powershellGetWindowsESUStatus(conn)
}
