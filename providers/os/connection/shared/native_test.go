// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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

func TestWindowsNativeEnabled(t *testing.T) {
	t.Setenv(WindowsNativeEnv, "")
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })

	plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)}))
	assert.False(t, WindowsNativeEnabled(), "off without the feature or the variable")

	plugin.ReadFeatures([]byte(mql.Features{byte(mql.WindowsNative)}))
	assert.True(t, WindowsNativeEnabled(), "the server's WindowsNative feature")

	plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)}))
	t.Setenv(WindowsNativeEnv, "1")
	assert.True(t, WindowsNativeEnabled(), "MONDOO_WINDOWS_NATIVE")
}

type typedConn struct {
	Connection
	t ConnectionType
}

func (c typedConn) Type() ConnectionType { return c.t }
