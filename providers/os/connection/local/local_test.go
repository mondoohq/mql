// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package local

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func runStderr(t *testing.T, command string) string {
	t.Helper()
	res, err := NewConnection(0, nil, &inventory.Asset{}).RunCommand(command)
	require.NoError(t, err)
	b, err := io.ReadAll(res.Stderr)
	require.NoError(t, err)
	return string(b)
}

// Stderr that is not PowerShell CLIXML reaches callers byte for byte.
func TestRunCommandStderrUnchanged(t *testing.T) {
	assert.Equal(t, "plain error\n  \n", runStderr(t, `printf 'plain error\n  \n' >&2; exit 2`))
}

// CLIXML on stderr is decoded by the transport, so every caller of
// RunCommand sees the error text. The fixture was captured over WinRM from
// powershell.exe on Windows Server 2022.
func TestRunCommandStderrCLIXMLDecoded(t *testing.T) {
	fixture := filepath.Join("..", "..", "resources", "powershell", "testdata", "clixml", "ws2022-get-item.txt")
	_, err := os.Stat(fixture)
	require.NoError(t, err)
	got := runStderr(t, "cat '"+fixture+"' >&2; exit 1")
	assert.True(t, strings.HasPrefix(got, "Get-Item : Cannot find path 'C:\\nope' because it does not exist.\r\n"), got)
	assert.NotContains(t, got, "CLIXML")
}
