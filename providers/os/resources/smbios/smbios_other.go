// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package smbios

import "go.mondoo.com/mql/providers/os/connection/shared"

func fetchWindowsSmbios(conn shared.Connection) (smbiosWindows, error) {
	return fetchWindowsSmbiosPowershell(conn)
}
