// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvEnabled(t *testing.T) {
	for _, v := range []string{"", "0", "false", "FALSE", "no", "off", " 0 "} {
		assert.False(t, envEnabled(v), "%q", v)
	}
	for _, v := range []string{"1", "true", "yes", "on", "native"} {
		assert.True(t, envEnabled(v), "%q", v)
	}
}

func TestWindowsNativeNeedsALocalWindowsConnection(t *testing.T) {
	t.Setenv(WindowsNativeEnv, "1")
	assert.False(t, WindowsNative(nil))
	if runtime.GOOS != "windows" {
		// The variable alone never switches a non-Windows scanner to Win32 calls.
		assert.False(t, WindowsNative(typedConn{t: Type_Local}))
	}
	// A remote connection keeps the PowerShell path wherever the provider runs.
	assert.False(t, WindowsNative(typedConn{t: Type_SSH}))
}

type typedConn struct {
	Connection
	t ConnectionType
}

func (c typedConn) Type() ConnectionType { return c.t }
