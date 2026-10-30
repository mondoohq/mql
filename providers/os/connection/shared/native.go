// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"os"
	"runtime"
	"strings"

	"go.mondoo.com/mql"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// WindowsNativeEnv switches on the native (Win32, registry) implementations of
// Windows resources locally, like the WindowsNative feature does when the
// server sends it.
const WindowsNativeEnv = "MONDOO_WINDOWS_NATIVE"

// WindowsNative reports whether a resource may use a native Windows
// implementation. Both halves are needed: a native call reads the machine the
// provider runs on, so it is only right for a local connection on Windows, and
// until a native path has shown it gives the same results as the PowerShell
// path it runs only when it is switched on (WindowsNativeEnabled). Otherwise a
// resource keeps its PowerShell path, so one build can be compared both ways
// on the same machine.
func WindowsNative(conn Connection) bool {
	if conn == nil || conn.Type() != Type_Local || runtime.GOOS != "windows" {
		return false
	}
	return WindowsNativeEnabled()
}

// WindowsNativeEnabled reports whether the native Windows implementations are
// switched on: by the WindowsNative feature, which the server steers per scan
// scope (or MONDOO_FEATURES / the config's features turn on locally), or by
// MONDOO_WINDOWS_NATIVE.
func WindowsNativeEnabled() bool {
	return plugin.FeatureActive(mql.WindowsNative) || envEnabled(os.Getenv(WindowsNativeEnv))
}

// envEnabled treats any value but "", 0, false, no and off as on.
func envEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "no", "off":
		return false
	}
	return true
}
