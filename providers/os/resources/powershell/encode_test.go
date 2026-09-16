// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package powershell_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/v13/providers/os/resources/powershell"
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
