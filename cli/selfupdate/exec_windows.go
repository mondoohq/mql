// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package selfupdate

import (
	"os"
	"os/exec"
)

// ExecUpdatedBinary spawns the updated binary and exits the current process.
// On Windows, syscall.Exec is not available, so we spawn a new process,
// wait for it to complete, and exit with its exit code.
func ExecUpdatedBinary(binaryPath string, args []string) error {
	// Set internal flag to skip binary self-update in the new process (prevents infinite loops).
	// We use a separate env var so that provider auto-update (which reads MONDOO_AUTO_UPDATE
	// via viper's AutomaticEnv) is not affected.
	os.Setenv(envBinarySelfUpdateSkip, "1")

	// On Windows, we spawn the new process and wait for it to complete
	cmd := exec.Command(binaryPath, args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ()

	err := cmd.Run()

	// Exit with the child's exit code
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			// If we couldn't even start the process, return the error
			return err
		}
	}

	os.Exit(exitCode)

	// This line is never reached but needed for the function signature
	return nil
}
