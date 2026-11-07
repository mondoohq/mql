// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package powershell_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"golang.org/x/text/encoding/unicode"
)

func TestPowershellEncoding(t *testing.T) {
	expected := "powershell.exe -NoProfile -EncodedCommand JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQA9ACcAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAnADsAZABpAHIAIAAiAGMAOgBcAHAAcgBvAGcAcgBhAG0AIABmAGkAbABlAHMAIgAgAA=="
	cmd := string("dir \"c:\\program files\" ")
	assert.Equal(t, expected, powershell.Encode(cmd))
}

func TestSplitInvocation(t *testing.T) {
	tests := []struct {
		name     string
		cmd      string
		wantArgv []string
		wantOK   bool
	}{
		{
			name:     "Encode output round-trips to direct argv",
			cmd:      powershell.Encode("Get-CimInstance -ClassName Win32_Bios"),
			wantArgv: []string{"powershell.exe", "-NoProfile", "-EncodedCommand", powershell.Encode("Get-CimInstance -ClassName Win32_Bios")[len("powershell.exe -NoProfile -EncodedCommand "):]},
			wantOK:   true,
		},
		{
			name:     "EncodeUnix output round-trips to direct argv",
			cmd:      powershell.EncodeUnix("hostname"),
			wantArgv: []string{"pwsh", "-NoProfile", "-EncodedCommand", powershell.EncodeUnix("hostname")[len("pwsh -NoProfile -EncodedCommand "):]},
			wantOK:   true,
		},
		{
			name:     "Wrap output unwraps to a single -c script",
			cmd:      powershell.Wrap("Get-NetAdapter | ConvertTo-Json"),
			wantArgv: []string{"powershell", "-c", "Get-NetAdapter | ConvertTo-Json"},
			wantOK:   true,
		},
		{
			name:   "plain command is not a powershell invocation",
			cmd:    "hostname",
			wantOK: false,
		},
		{
			name:   "non-powershell binary is left alone",
			cmd:    "cmd /c echo hi",
			wantOK: false,
		},
		{
			name:   "empty encoded payload is rejected",
			cmd:    "powershell.exe -NoProfile -EncodedCommand ",
			wantOK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			argv, ok := powershell.SplitInvocation(tc.cmd)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantArgv, argv)
			}
		})
	}
}

// MaxScriptLength is a magic number, so derive the real ceiling by binary
// search over Encode rather than trusting the arithmetic. If Encode ever grows
// another prefix, this fails and the constant has to come down with it.
func TestMaxScriptLengthIsUnderTheRealCeiling(t *testing.T) {
	fits := func(n int) bool {
		return len(powershell.Encode(strings.Repeat("a", n))) <= powershell.MaxCommandLength
	}

	lo, hi := 0, 16384 // hi is known not to fit
	for lo+1 < hi {
		mid := (lo + hi) / 2
		if fits(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	ceiling := lo

	assert.Equal(t, 3016, ceiling,
		"the measured script ceiling moved; update powershell.MaxScriptLength")
	assert.True(t, fits(ceiling))
	assert.False(t, fits(ceiling+1))

	assert.LessOrEqual(t, powershell.MaxScriptLength, ceiling,
		"MaxScriptLength must stay at or below the measured ceiling")
	assert.True(t, powershell.FitsCommandLine(strings.Repeat("a", powershell.MaxScriptLength)))
}

func TestWithUTF8Output(t *testing.T) {
	decode := func(t *testing.T, command string) string {
		t.Helper()
		argv, ok := powershell.SplitInvocation(command)
		require.True(t, ok, command)
		require.Equal(t, "-EncodedCommand", argv[2])
		raw, err := base64.StdEncoding.DecodeString(argv[3])
		require.NoError(t, err)
		text, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(raw)
		require.NoError(t, err)
		return string(text)
	}

	// Synthetic: the script keeps every character, including Shift-JIS
	// characters whose second byte is a backslash (ソ 83 5C, 表 95 5C).
	t.Run("Encode form", func(t *testing.T) {
		got, ok := powershell.WithUTF8Output(powershell.Encode("Get-LocalUser -Name 'ソ表'"))
		require.True(t, ok)
		assert.True(t, strings.HasPrefix(got, "powershell.exe -NoProfile -EncodedCommand "), got)
		assert.Equal(t,
			"[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue';Get-LocalUser -Name 'ソ表'",
			decode(t, got))
	})

	t.Run("Wrap form", func(t *testing.T) {
		got, ok := powershell.WithUTF8Output(powershell.Wrap("Get-NetAdapter | ConvertTo-Json"))
		require.True(t, ok)
		assert.Equal(t, `powershell -c "[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-NetAdapter | ConvertTo-Json"`, got)
	})

	// Synthetic: commands the rewrite must leave alone.
	for name, cmd := range map[string]string{
		"pwsh on Unix":        powershell.EncodeUnix("Get-Date"),
		"plain command":       "ipconfig /all",
		"cmd.exe":             "cmd /c echo hi",
		"staged script":       powershell.StagedCommand(`C:\Windows\Temp\users-0123456789ab.ps1`),
		"payload not base64":  "powershell.exe -NoProfile -EncodedCommand !!!",
		"payload odd UTF-16":  "powershell.exe -NoProfile -EncodedCommand " + base64.StdEncoding.EncodeToString([]byte("abc")),
		"script at the cap":   powershell.Encode(strings.Repeat("a", 3016)),
		"astral chars at cap": powershell.Wrap(strings.Repeat("𝄞", 4100)),
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := powershell.WithUTF8Output(cmd)
			assert.False(t, ok, got)
		})
	}

	// Synthetic: a script under MaxScriptLength minus the statement still fits.
	t.Run("long script that still fits", func(t *testing.T) {
		_, ok := powershell.WithUTF8Output(powershell.Encode(strings.Repeat("a", 2900)))
		assert.True(t, ok)
	})
}
