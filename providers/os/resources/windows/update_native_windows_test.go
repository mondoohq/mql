// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"bytes"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NativeWUAResults must report what WINDOWS_QUERY_WUA_RESULTS reports on the
// same host.
func TestNativeWUAResultsMatchesPowerShell(t *testing.T) {
	native, err := NativeWUAResults()
	require.NoError(t, err)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_QUERY_WUA_RESULTS)
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("PowerShell path unavailable: %v", err)
	}
	ps, err := ParseWUAResults(bytes.NewReader(out))
	require.NoError(t, err)

	assert.Equal(t, ps, native)
}
