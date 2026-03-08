// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package selfupdate

import (
	"os"
	"syscall"
)

// ExecUpdatedBinary replaces the current process with the updated binary.
// On Unix systems, this uses syscall.Exec which replaces the current process entirely.
func ExecUpdatedBinary(binaryPath string, args []string) error {
	// Set internal flag to skip binary self-update in the new process (prevents infinite loops).
	// We use a separate env var so that provider auto-update (which reads MONDOO_AUTO_UPDATE
	// via viper's AutomaticEnv) is not affected.
	os.Setenv(envBinarySelfUpdateSkip, "1")

	// Replace the current process with the new binary
	// syscall.Exec replaces the current process image with the new one
	return syscall.Exec(binaryPath, args, os.Environ())
}
