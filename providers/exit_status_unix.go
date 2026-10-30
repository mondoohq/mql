// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package providers

import (
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// signalName returns the conventional "SIGKILL"-style name for a signal,
// falling back to Go's prose rendering ("killed") for unnamed signals.
func signalName(sig syscall.Signal) string {
	if name := unix.SignalName(unix.Signal(sig)); name != "" {
		return name
	}
	return sig.String()
}

// maxRSSBytes returns the process's peak resident set size in bytes, or 0 if
// unavailable. Reported unit-free in bytes so downstream log aggregation can
// consume the value without unit parsing.
func maxRSSBytes(ps *os.ProcessState) int64 {
	if ps == nil {
		return 0
	}
	ru, ok := ps.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		return 0
	}
	switch runtime.GOOS {
	case "darwin", "ios":
		// macOS reports ru_maxrss in bytes
		return int64(ru.Maxrss)
	default:
		// Linux and the BSDs report ru_maxrss in kilobytes
		return int64(ru.Maxrss) * 1024
	}
}
