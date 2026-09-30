// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package powershell

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A script that cannot be encoded must not turn into an -EncodedCommand with
// an empty payload, which runs as a no-op and exits 0: the command fails
// with a message instead.
func TestEncodeFailureFailsLoudly(t *testing.T) {
	failing := func(string) (string, error) { return "", errors.New("boom") }
	cmd := encodeWith("powershell.exe", "Get-Date", failing)
	assert.NotContains(t, cmd, "-EncodedCommand")
	assert.Contains(t, cmd, "throw")
	assert.True(t, strings.HasPrefix(cmd, "powershell.exe -NoProfile -Command "))

	empty := func(string) (string, error) { return "", nil }
	assert.NotContains(t, encodeWith("pwsh", "Get-Date", empty), "-EncodedCommand")
}

// Wrap keeps the plain form for scripts without a double quote, and encodes
// the ones with one, which would otherwise end the -c argument early.
func TestWrapEncodesDoubleQuotes(t *testing.T) {
	assert.Equal(t, `powershell -c "Get-Service | ConvertTo-Json"`, Wrap("Get-Service | ConvertTo-Json"))

	quoted := `Get-Item "HKLM:\SOFTWARE" | ConvertTo-Json`
	cmd := Wrap(quoted)
	assert.Equal(t, Encode(quoted), cmd)
	argv, ok := SplitInvocation(cmd)
	require.True(t, ok)
	assert.Equal(t, []string{"powershell.exe", "-NoProfile", "-EncodedCommand"}, argv[:3])
}
