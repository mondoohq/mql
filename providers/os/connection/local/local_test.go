// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package local

import (
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"golang.org/x/text/encoding/unicode"
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

// Synthetic: a Windows host's OEM code page (932 on a Japanese one) would
// garble every non-ASCII character, so PowerShell invocations run with their
// output switched to UTF-8.
func TestUnnestPowershellWritesUTF8(t *testing.T) {
	windowsShell := []string{"powershell", "-c"}

	argv, ok := unnestPowershell(windowsShell, powershell.Wrap("Get-LocalUser | ConvertTo-Json"))
	require.True(t, ok)
	assert.Equal(t, []string{"powershell", "-c", "[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-LocalUser | ConvertTo-Json"}, argv)

	argv, ok = unnestPowershell(windowsShell, powershell.Encode("Get-LocalUser"))
	require.True(t, ok)
	require.Len(t, argv, 4)
	raw, err := base64.StdEncoding.DecodeString(argv[3])
	require.NoError(t, err)
	script, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(raw)
	require.NoError(t, err)
	assert.Equal(t, "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue';Get-LocalUser", string(script))

	// a staged script runs as it is; the file starts with the statement
	_, ok = unnestPowershell(windowsShell, powershell.StagedCommand(`C:\Windows\Temp\users-0123456789ab.ps1`))
	assert.False(t, ok)

	// the unix shell never unnests
	_, ok = unnestPowershell([]string{"sh", "-c"}, powershell.Encode("Get-LocalUser"))
	assert.False(t, ok)
}
