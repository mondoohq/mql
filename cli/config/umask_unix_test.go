// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package config

import (
	"os"
	"syscall"
)

// umaskBits returns the process umask, which narrows the mode MkdirAll applies.
func umaskBits() os.FileMode {
	m := syscall.Umask(0)
	syscall.Umask(m)
	return os.FileMode(m)
}
