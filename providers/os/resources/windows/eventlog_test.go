// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEventLogChannel(t *testing.T) {
	t.Run("a classic log", func(t *testing.T) {
		input := `{"LogName":"Security","IsEnabled":true,"IsClassicLog":true,"LogFilePath":"%SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx","SystemRoot":"C:\\Windows","RecordCount":21874}`

		ch, err := ParseEventLogChannel(strings.NewReader(input))
		require.NoError(t, err)
		assert.Equal(t, "Security", ch.LogName)
		assert.True(t, ch.IsEnabled)
		assert.True(t, ch.IsClassicLog)
		assert.Equal(t, `C:\Windows\System32\Winevt\Logs\Security.evtx`, ch.ExpandedLogFilePath())
		assert.Equal(t, int64(21874), ch.RecordCount)
	})

	// The reason these fields exist: a modern provider channel is not under
	// Services\EventLog at all, so the registry-only reading reported it as
	// unconfigured rather than as a real channel.
	t.Run("a modern provider channel", func(t *testing.T) {
		input := `{"LogName":"Microsoft-Windows-PowerShell/Operational","IsEnabled":true,"IsClassicLog":false,"LogFilePath":"%SystemRoot%\\System32\\Winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx","SystemRoot":"C:\\Windows","RecordCount":142}`

		ch, err := ParseEventLogChannel(strings.NewReader(input))
		require.NoError(t, err)
		assert.Equal(t, "Microsoft-Windows-PowerShell/Operational", ch.LogName)
		assert.False(t, ch.IsClassicLog)
		assert.True(t, ch.IsEnabled)
		assert.Equal(t, int64(142), ch.RecordCount)
		// the %4 in the file name is an escaped separator, not a variable, and
		// must survive expansion untouched
		assert.Equal(t,
			`C:\Windows\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`,
			ch.ExpandedLogFilePath())
	})

	t.Run("a disabled channel holding nothing", func(t *testing.T) {
		input := `{"LogName":"Microsoft-Windows-Kernel-Boot/Analytic","IsEnabled":false,"IsClassicLog":false,"LogFilePath":"%SystemRoot%\\System32\\Winevt\\Logs\\x.etl","SystemRoot":"C:\\Windows","RecordCount":0}`

		ch, err := ParseEventLogChannel(strings.NewReader(input))
		require.NoError(t, err)
		assert.False(t, ch.IsEnabled)
		assert.Equal(t, int64(0), ch.RecordCount)
	})

	// Empty output means the command produced no object. Decoding it to a zero
	// value would report the channel as disabled and holding no events, which
	// is the reading that makes an audit pass on a channel nobody looked at.
	t.Run("empty output is an error, not a disabled channel", func(t *testing.T) {
		for _, input := range []string{``, "   \n"} {
			_, err := ParseEventLogChannel(strings.NewReader(input))
			assert.Error(t, err, "input %q", input)
		}
	})

	t.Run("malformed output is an error", func(t *testing.T) {
		_, err := ParseEventLogChannel(strings.NewReader(`{"LogName":`))
		assert.Error(t, err)
	})
}

func TestEventLogChannelScript(t *testing.T) {
	// A channel name is interpolated into the script, so it is single quoted
	// and a quote in it is doubled. Nothing else is escaped inside a
	// PowerShell single-quoted string, which is what keeps a backslash a
	// backslash.
	script := EventLogChannelScript("Microsoft-Windows-PowerShell/Operational")
	assert.Contains(t, script, `-ListLog 'Microsoft-Windows-PowerShell/Operational'`)

	assert.Contains(t, EventLogChannelScript("it's odd"), `'it''s odd'`)

	// The system root is carried out as data and substituted in Go. A static
	// method call is refused outright in ConstrainedLanguage mode, which WDAC
	// and AppLocker put a host into, and the refusal fails the whole payload
	// rather than just that one value: on a live host in that mode, a single
	// ExpandEnvironmentVariables call took enabled, isClassicLog and
	// recordCount down with it.
	assert.NotContains(t, script, "ExpandEnvironmentVariables")
	assert.NotContains(t, script, "::", "no static method call may appear in this script")
	assert.Contains(t, script, "$env:SystemRoot")

	assert.LessOrEqual(t, len(script), PSMaxScriptLength)
}

func TestExpandWindowsPath(t *testing.T) {
	const root = `C:\Windows`

	t.Run("the shape Windows actually stores", func(t *testing.T) {
		assert.Equal(t,
			`C:\Windows\System32\Winevt\Logs\Application.evtx`,
			expandWindowsPath(`%SystemRoot%\System32\Winevt\Logs\Application.evtx`, root))
	})

	// The registry value and the documentation disagree on casing, so the
	// match cannot be case sensitive or a real path goes unexpanded.
	t.Run("matching is case insensitive", func(t *testing.T) {
		for _, v := range []string{
			`%SystemRoot%\a.evtx`,
			`%systemroot%\a.evtx`,
			`%SYSTEMROOT%\a.evtx`,
			`%WinDir%\a.evtx`,
			`%windir%\a.evtx`,
		} {
			assert.Equal(t, `C:\Windows\a.evtx`, expandWindowsPath(v, root), "input %q", v)
		}
	})

	t.Run("a non-default system root is honored", func(t *testing.T) {
		assert.Equal(t, `D:\Win\a.evtx`, expandWindowsPath(`%SystemRoot%\a.evtx`, `D:\Win`))
		// a trailing separator must not double up
		assert.Equal(t, `D:\Win\a.evtx`, expandWindowsPath(`%SystemRoot%\a.evtx`, `D:\Win\`))
	})

	t.Run("an already absolute path is left alone", func(t *testing.T) {
		assert.Equal(t, `E:\logs\custom.evtx`, expandWindowsPath(`E:\logs\custom.evtx`, root))
	})

	// Half expanding would hand out a path that cannot be opened while looking
	// like one that can. Returning it as stored keeps it obviously unresolved.
	t.Run("an unknown variable is left as stored", func(t *testing.T) {
		assert.Equal(t, `%LogRoot%\a.evtx`, expandWindowsPath(`%LogRoot%\a.evtx`, root))
	})

	t.Run("an unknown system root leaves the path as stored", func(t *testing.T) {
		assert.Equal(t, `%SystemRoot%\a.evtx`, expandWindowsPath(`%SystemRoot%\a.evtx`, ""))
	})
}
