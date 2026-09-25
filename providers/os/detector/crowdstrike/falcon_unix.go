// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package crowdstrike

import "go.mondoo.com/mql/providers/os/connection/shared"

func detectWindows(conn shared.Connection) *Identity {
	return powershellDetectWindows(conn)
}
