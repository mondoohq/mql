// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package winrm

import (
	"testing"
	"unicode/utf16"

	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// Windows measures a command line in UTF-16 code units. Neither obvious
// shorthand matches that: len() counts UTF-8 bytes and over-counts anything
// non-ASCII, RuneCountInString counts code points and under-counts anything
// outside the basic multilingual plane.
func TestUtf16Len(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want int
	}{
		{"empty", "", 0},
		{"ascii", "powershell.exe -NoProfile", 25},
		// 2 bytes in UTF-8, 1 UTF-16 code unit
		{"latin1", "é", 1},
		// 3 bytes in UTF-8, 1 UTF-16 code unit -- a ja-JP path
		{"cjk", "C:\\ユーザー", 7},
		// 4 bytes in UTF-8, 2 UTF-16 code units: the case RuneCountInString
		// gets wrong
		{"supplementary", "\U0001F600", 2},
		{"mixed", "a\U0001F600é", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, utf16Len(tc.in))
			// agree with the standard library's encoder, which is the
			// definition of the unit
			assert.Equal(t, len(utf16.Encode([]rune(tc.in))), utf16Len(tc.in))
		})
	}
}

// The two shorthands this helper exists to avoid disagree with it in opposite
// directions, which is why neither was used.
func TestUtf16Len_DiffersFromBytesAndRunes(t *testing.T) {
	cjk := "ユーザー"
	assert.Greater(t, len(cjk), utf16Len(cjk), "byte length over-counts, and would refuse commands that fit")

	emoji := "\U0001F600\U0001F600"
	assert.Less(t, len([]rune(emoji)), utf16Len(emoji), "rune count under-counts, and would let a truncated command through")
}

// TestRunCommandRejectsOverLongCommand covers the guard itself rather than the
// counter behind it.
//
// The connection carries no client on purpose: the guard has to fire before
// anything touches it, which is also what makes this testable without a
// Windows host. If the check were ever moved below the client call, this test
// would panic instead of returning an error.
func TestRunCommandRejectsOverLongCommand(t *testing.T) {
	conn := &Connection{}
	cmd := strings.Repeat("a", powershell.MaxCommandLength+1)

	res, err := conn.RunCommand(cmd)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "would be truncated before it ran",
		"the error has to say why, or it reads like a transport failure")
	assert.Contains(t, err.Error(), strconv.Itoa(powershell.MaxCommandLength+1),
		"the error names the actual length")
	require.NotNil(t, res, "the command result is still returned for timing")
	assert.Equal(t, cmd, res.Command)
}

// The boundary case. A command exactly at the limit is allowed through, which
// here means it reaches the nil client and panics - that panic is the
// observation: the guard is not what stopped it. An off-by-one in the
// comparison would return an error instead and fail this.
func TestRunCommandAllowsCommandAtTheLimit(t *testing.T) {
	defer func() {
		assert.NotNil(t, recover(),
			"a command at exactly the limit must pass the guard and reach the client")
	}()

	conn := &Connection{}
	_, _ = conn.RunCommand(strings.Repeat("a", powershell.MaxCommandLength))

	t.Fatal("expected to reach the client rather than return from the guard")
}

// The limit is measured in UTF-16 code units, which is what Windows counts.
// Each of these emoji is one rune but two UTF-16 units, so a command that
// utf8.RuneCountInString would call comfortably short is actually over - the
// exact case a rune-based check would wave through to be truncated.
func TestRunCommandCountsUtf16NotRunes(t *testing.T) {
	conn := &Connection{}
	cmd := strings.Repeat("😀", powershell.MaxCommandLength/2+1)

	require.Less(t, utf8.RuneCountInString(cmd), powershell.MaxCommandLength,
		"the fixture must be short in runes, or it proves nothing")

	_, err := conn.RunCommand(cmd)

	require.Error(t, err, "over the limit in UTF-16 units, so it must be rejected")
}
