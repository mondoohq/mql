// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"os"
	"runtime"
	"strings"
)

// WindowsNativeEnv switches on the native (Win32, registry) implementations of
// Windows resources that are still being introduced.
const WindowsNativeEnv = "MONDOO_WINDOWS_NATIVE"

// WindowsNative reports whether a resource may use a native Windows
// implementation that is behind MONDOO_WINDOWS_NATIVE. Both halves are needed:
// a native call reads the machine the provider runs on, so it is only right for
// a local connection on Windows, and until a native path has shown it gives the
// same results as the PowerShell path it runs only when the variable is set.
// Without it a resource keeps its PowerShell path, so one build can be compared
// both ways on the same machine.
func WindowsNative(conn Connection) bool {
	if conn == nil || conn.Type() != Type_Local || runtime.GOOS != "windows" {
		return false
	}
	return envEnabled(os.Getenv(WindowsNativeEnv))
}

// envEnabled treats any value but "", 0, false, no and off as on.
func envEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "no", "off":
		return false
	}
	return true
}
