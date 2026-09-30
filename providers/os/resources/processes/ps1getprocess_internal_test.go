// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

func TestProcessName(t *testing.T) {
	assert.Equal(t, "cmd", processName(`C:\Windows\System32\cmd.exe`))
	assert.Equal(t, "MsMpEng", processName(`C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.EXE`))
	assert.Equal(t, "Registry", processName("Registry"))
	assert.Equal(t, "tool.com", processName(`C:\bin\tool.com`))
}

func TestParseWindowsProcessByID(t *testing.T) {
	p, err := parseWindowsProcessByID(strings.NewReader(""), 42)
	require.NoError(t, err)
	assert.Nil(t, p, "no output means the pid does not exist")

	p, err = parseWindowsProcessByID(strings.NewReader(`{"Name":"cmd","Id":42,"Path":"C:\\Windows\\System32\\cmd.exe"}`), 42)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, int64(42), p.Pid)
	assert.Equal(t, "cmd", p.Executable)
	assert.Equal(t, `C:\Windows\System32\cmd.exe`, p.Command)

	p, err = parseWindowsProcessByID(strings.NewReader(`{"Name":"cmd","Id":7}`), 42)
	require.NoError(t, err)
	assert.Nil(t, p, "another pid is not this process")
}

// Exists and Process answer over PowerShell (the path of every remote scan,
// and of local scans without MONDOO_WINDOWS_NATIVE).
func TestWindowsProcessManagerByID(t *testing.T) {
	cmd := func(pid int64) string { return powershell.Encode(fmt.Sprintf(ps1GetProcessByID, pid)) }
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{Commands: map[string]*mock.Command{
		cmd(4):  {Stdout: `{"Name":"System","Id":4,"Path":null}`},
		cmd(99): {Stdout: ""},
	}}))
	require.NoError(t, err)
	wpm := &WindowsProcessManager{conn: conn}

	exists, err := wpm.Exists(4)
	require.NoError(t, err)
	assert.True(t, exists)

	p, err := wpm.Process(4)
	require.NoError(t, err)
	assert.Equal(t, "System", p.Executable)

	exists, err = wpm.Exists(99)
	require.NoError(t, err)
	assert.False(t, exists)

	_, err = wpm.Process(99)
	assert.ErrorContains(t, err, "process 99 does not exist")
}
