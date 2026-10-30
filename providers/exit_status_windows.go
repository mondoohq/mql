// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package providers

import (
	"os"
	"syscall"
)

// signalName falls back to Go's rendering; Windows processes are never
// signal-killed in the POSIX sense, so this path is effectively unused there.
func signalName(sig syscall.Signal) string {
	return sig.String()
}

// maxRSSBytes is unavailable on Windows: syscall.Rusage there only carries
// process times, not memory counters.
func maxRSSBytes(ps *os.ProcessState) int64 {
	return 0
}
