// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build linux || darwin || netbsd || openbsd || freebsd
// +build linux darwin netbsd openbsd freebsd

package windows

import "go.mondoo.com/mql/providers/os/connection/shared"

// GetIntuneInfo returns the Intune enrollment ID and the device certificates
// of a remote Windows system.
func GetIntuneInfo(conn shared.Connection) (*IntuneInfo, error) {
	return powershellGetIntuneInfo(conn)
}
