// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"bytes"
	"encoding/base64"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"golang.org/x/text/encoding/unicode"
)

func TestParseShellProbe(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   remoteShell
	}{
		{"cmd.exe", "Windows_NT;$PSVersionTable.PSEdition\r\n", shellCmd},
		{"windows powershell", "%OS%\r\nDesktop\r\n", shellWindowsPowerShell},
		{"pwsh", "%OS%\nCore\n", shellPwsh},
		{"sh", "%OS%\n", shellPosix},
		{"empty", "", shellUnknown},
		{"something else", "hello\n", shellUnknown},
		{"edition inside a line", "%OS%\r\nnot Desktop\r\n", shellUnknown},
		{"trailing blank lines", "%OS%\r\nDesktop\r\n\r\n", shellWindowsPowerShell},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseShellProbe(tc.stdout))
		})
	}
}

func decodeDirect(t *testing.T, direct string) string {
	t.Helper()
	const prefix = "Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('"
	suffix := "')))" + directStreams
	require.True(t, strings.HasPrefix(direct, prefix), direct)
	require.True(t, strings.HasSuffix(direct, suffix), direct)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(direct, prefix), suffix))
	require.NoError(t, err)
	script, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(raw)
	require.NoError(t, err)
	return string(script)
}

func TestDirectPowershell(t *testing.T) {
	t.Run("encoded windows powershell", func(t *testing.T) {
		script := `Get-Item "C:\Program Files" | ConvertTo-Json; $x = 'é'`
		direct, ok := directPowershell(powershell.Encode(script))
		require.True(t, ok)
		assert.NotContains(t, direct, `"`, "the server's shell receives the command inside double quotes")
		assert.Equal(t, "$ProgressPreference='SilentlyContinue';"+script+"\nif (-not $?) { exit 1 }", decodeDirect(t, direct))
	})

	for _, cmd := range []string{
		powershell.EncodeUnix("Get-Date"),    // pwsh is another PowerShell
		powershell.Wrap("Get-Date"),          // not encoded
		powershell.StagedCommand(`C:\x.ps1`), // a file
		"uname -s",
		"ipconfig /all",
		"",
	} {
		t.Run(cmd, func(t *testing.T) {
			_, ok := directPowershell(cmd)
			assert.False(t, ok)
		})
	}
}

// fakeRunner records the commands a connection sends and answers the shell
// probe like the given shell.
type fakeRunner struct {
	mu    sync.Mutex
	shell string
	sent  []string
}

func (f *fakeRunner) run(command string) (*shared.Command, error) {
	f.mu.Lock()
	f.sent = append(f.sent, command)
	f.mu.Unlock()
	out := "ran"
	if command == shellProbe {
		out = f.shell
	}
	return &shared.Command{
		Command: command,
		Stdout:  bytes.NewBufferString(out),
		Stderr:  &bytes.Buffer{},
	}, nil
}

func (f *fakeRunner) probes() int {
	n := 0
	for _, c := range f.sent {
		if c == shellProbe {
			n++
		}
	}
	return n
}

func newFakeConnection(f *fakeRunner) *Connection {
	return &Connection{conf: &inventory.Config{}, rawRunner: f.run}
}

func TestRunCommandPowershellDefaultShell(t *testing.T) {
	f := &fakeRunner{shell: "%OS%\r\nDesktop\r\n"}
	c := newFakeConnection(f)
	cmd := powershell.Encode("Get-Date")

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := c.RunCommand(cmd)
			require.NoError(t, err)
			// callers and recordings see the command they asked for
			assert.Equal(t, cmd, res.Command)
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, f.probes(), "the shell is detected once per connection")
	for _, sent := range f.sent {
		assert.NotContains(t, sent, "powershell.exe", "no second powershell.exe")
	}

	// other commands are sent as they are
	_, err := c.RunCommand("ipconfig /all")
	require.NoError(t, err)
	assert.Equal(t, "ipconfig /all", f.sent[len(f.sent)-1])
}

func TestRunCommandKeepsPowershellExeForOtherShells(t *testing.T) {
	for name, probe := range map[string]string{
		"cmd.exe": "Windows_NT;$PSVersionTable.PSEdition\r\n",
		"pwsh":    "%OS%\nCore\n",
		"unknown": "",
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeRunner{shell: probe}
			c := newFakeConnection(f)
			cmd := powershell.Encode("Get-Date")
			_, err := c.RunCommand(cmd)
			require.NoError(t, err)
			_, err = c.RunCommand(cmd)
			require.NoError(t, err)
			assert.Equal(t, []string{shellProbe, cmd, cmd}, f.sent)
		})
	}
}

func TestRunCommandUnixNeverProbes(t *testing.T) {
	f := &fakeRunner{shell: "%OS%\n"}
	c := newFakeConnection(f)
	for _, cmd := range []string{"uname -s", "cat /etc/os-release", powershell.EncodeUnix("Get-Date")} {
		_, err := c.RunCommand(cmd)
		require.NoError(t, err)
	}
	assert.Equal(t, 0, f.probes())
}

func TestRunCommandSudoIsNotRewritten(t *testing.T) {
	f := &fakeRunner{shell: "%OS%\r\nDesktop\r\n"}
	c := newFakeConnection(f)
	c.Sudo = &inventory.Sudo{Active: true, Executable: "sudo"}
	_, err := c.RunCommand(powershell.Encode("Get-Date"))
	require.NoError(t, err)
	assert.Equal(t, 0, f.probes())
	require.Len(t, f.sent, 1)
	assert.True(t, strings.HasPrefix(f.sent[0], "sudo "), f.sent[0])
}
