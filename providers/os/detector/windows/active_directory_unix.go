// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package windows

import "go.mondoo.com/mql/providers/os/connection/shared"

// GetActiveDirectoryInfo returns the Active Directory domain membership of a
// remote Windows system.
func GetActiveDirectoryInfo(conn shared.Connection) (*ActiveDirectoryInfo, error) {
	return powershellGetActiveDirectoryInfo(conn)
}
