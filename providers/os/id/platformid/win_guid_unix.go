// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build linux || darwin || netbsd || openbsd || freebsd

package platformid

import "go.mondoo.com/mql/providers/os/connection/shared"

func windowsMachineId(conn shared.Connection) (string, error) {
	return PowershellWindowsMachineId(conn)
}
