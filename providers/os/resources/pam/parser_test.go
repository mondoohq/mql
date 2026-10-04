// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pam

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func TestParseLine(t *testing.T) {
	t.Run("parsing conf lines", func(t *testing.T) {
		line := "account    required       pam_opendirectory.so"
		expected := &PamLine{
			PamType: "account",
			Control: "required",
			Module:  "pam_opendirectory.so",
			Options: []any{},
		}
		result, err := ParseLine(line)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("parsing conf lines with options", func(t *testing.T) {
		line := "account    required       pam_opendirectory.so no_warn group=admin,wheel"
		expected := &PamLine{
			PamType: "account",
			Control: "required",
			Module:  "pam_opendirectory.so",
			Options: []any{"no_warn", "group=admin,wheel"},
		}
		result, err := ParseLine(line)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("parsing conf lines with complicated control", func(t *testing.T) {
		line := "account     [default=bad success=ok user_unknown=ignore] pam_sss.so"
		expected := &PamLine{
			PamType: "account",
			Control: "[default=bad success=ok user_unknown=ignore]",
			Module:  "pam_sss.so",
			Options: []any{},
		}
		result, err := ParseLine(line)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("parsing conf lines with complicated control and options", func(t *testing.T) {
		line := "account    [default=bad success=ok user_unknown=ignore]       pam_opendirectory.so no_warn group=admin,wheel"
		expected := &PamLine{
			PamType: "account",
			Control: "[default=bad success=ok user_unknown=ignore]",
			Module:  "pam_opendirectory.so",
			Options: []any{"no_warn", "group=admin,wheel"},
		}
		result, err := ParseLine(line)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("parsing conf lines with complicated control and options", func(t *testing.T) {
		line := "account    [default=bad]       pam_opendirectory.so no_warn group=admin,wheel"
		expected := &PamLine{
			PamType: "account",
			Control: "[default=bad]",
			Module:  "pam_opendirectory.so",
			Options: []any{"no_warn", "group=admin,wheel"},
		}
		result, err := ParseLine(line)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("parsing conf lines with a literal # inside an option", func(t *testing.T) {
		line := "password   required       pam_passwdqc.so config=/etc/passwdqc.conf match=*#*"
		expected := &PamLine{
			PamType: "password",
			Control: "required",
			Module:  "pam_passwdqc.so",
			Options: []any{"config=/etc/passwdqc.conf", "match=*#*"},
		}
		result, err := ParseLine(line)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("parsing conf lines with a trailing comment", func(t *testing.T) {
		line := "auth       required       pam_unix.so nullok # comment text"
		expected := &PamLine{
			PamType: "auth",
			Control: "required",
			Module:  "pam_unix.so",
			Options: []any{"nullok"},
		}
		result, err := ParseLine(line)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("parsing conf line with include", func(t *testing.T) {
		line := "@include common-password"
		expected := &PamLine{
			PamType: "@include",
			Control: "common-password",
			Module:  "",
			Options: []any{},
		}
		result, err := ParseLine(line)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("bracketed control running to end of line does not panic", func(t *testing.T) {
		// A bracketed control with no module following it is malformed; it must
		// return an error rather than panic with an out-of-range index.
		require.NotPanics(t, func() {
			_, err := ParseLine("auth [success=1 default=ignore]")
			require.Error(t, err)
		})
	})

	t.Run("unterminated bracketed control does not panic", func(t *testing.T) {
		require.NotPanics(t, func() {
			_, err := ParseLine("auth [success=1 default=ignore pam_unix.so")
			require.Error(t, err)
		})
	})

	t.Run("leading dash on the type", func(t *testing.T) {
		// from Rocky Linux 9's authselect system-auth
		result, err := ParseLine("-session    optional    pam_systemd.so")
		require.NoError(t, err)
		require.Equal(t, &PamLine{
			PamType:       "session",
			Control:       "optional",
			Module:        "pam_systemd.so",
			Options:       []any{},
			IgnoreMissing: true,
		}, result)
	})

	t.Run("leading dash on the type with a bracketed control", func(t *testing.T) {
		result, err := ParseLine("-auth [success=1 default=ignore] pam_sss.so use_first_pass")
		require.NoError(t, err)
		require.Equal(t, &PamLine{
			PamType:       "auth",
			Control:       "[success=1 default=ignore]",
			Module:        "pam_sss.so",
			Options:       []any{"use_first_pass"},
			IgnoreMissing: true,
		}, result)
	})

	t.Run("bracketed control with closing bracket in last token before module", func(t *testing.T) {
		// Regression: the closing `]` lands in the final field that the loop
		// previously refused to inspect.
		line := "auth [success=1 default=ignore] pam_unix.so"
		expected := &PamLine{
			PamType: "auth",
			Control: "[success=1 default=ignore]",
			Module:  "pam_unix.so",
			Options: []any{},
		}
		result, err := ParseLine(line)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})
}

func parsePamContent(content string) ([]*PamLine, error) {
	entries := []*PamLine{}
	lines := strings.Split(content, "\n")
	for i := range lines {
		line := lines[i]
		entry, err := ParseLine(line)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func TestSimplePamConfigurationFile(t *testing.T) {
	data, err := os.ReadFile("./testdata/simple")
	require.NoError(t, err)
	content := string(data)

	expected := []*PamLine{
		nil,
		{
			PamType: "auth",
			Control: "required",
			Module:  "pam_securetty.so",
			Options: []any{},
		},
		{
			PamType: "auth",
			Control: "required",
			Module:  "pam_unix.so",
			Options: []any{
				"nullok",
			},
		},
		{
			PamType: "auth",
			Control: "required",
			Module:  "pam_nologin.so",
			Options: []any{},
		},
		{
			PamType: "account",
			Control: "required",
			Module:  "pam_unix.so",
			Options: []any{},
		},
		{
			PamType: "password",
			Control: "required",
			Module:  "pam_cracklib.so",
			Options: []any{
				"retry=3",
			},
		},
		{
			PamType: "password",
			Control: "required",
			Module:  "pam_unix.so",
			Options: []any{
				"shadow",
				"nullok",
				"use_authtok",
			},
		},
		{
			PamType: "session",
			Control: "required",
			Module:  "pam_unix.so",
			Options: []any{},
		},
	}
	entries, err := parsePamContent(content)
	require.NoError(t, err)
	assert.Equal(t, expected, entries)
}

func TestRebootPamConfigurationFile(t *testing.T) {
	data, err := os.ReadFile("./testdata/reboot")
	require.NoError(t, err)
	content := string(data)

	expected := []*PamLine{
		nil,
		{
			PamType: "auth",
			Control: "sufficient",
			Module:  "pam_rootok.so",
			Options: []any{},
		},
		{
			PamType: "auth",
			Control: "required",
			Module:  "pam_console.so",
			Options: []any{},
		},
		nil,
		{
			PamType: "account",
			Control: "required",
			Module:  "pam_permit.so",
			Options: []any{},
		},
	}
	entries, err := parsePamContent(content)
	require.NoError(t, err)
	assert.Equal(t, expected, entries)
}

func TestCommonSessionNonInteractivePamConfigurationFile(t *testing.T) {
	data, err := os.ReadFile("./testdata/common-session-noninteractive")
	require.NoError(t, err)
	content := string(data)

	expected := []*PamLine{
		{
			PamType: "session",
			Control: "[default=1]",
			Module:  "pam_permit.so",
			Options: []any{},
		},
		{
			PamType: "session",
			Control: "requisite",
			Module:  "pam_deny.so",
			Options: []any{},
		},
		{
			PamType: "session",
			Control: "required",
			Module:  "pam_permit.so",
			Options: []any{},
		},
		{
			PamType: "session",
			Control: "optional",
			Module:  "pam_umask.so",
			Options: []any{},
		},
		{
			PamType: "session",
			Control: "required",
			Module:  "pam_unix.so",
			Options: []any{},
		},
		{
			PamType: "session",
			Control: "optional",
			Module:  "pam_ecryptfs.so",
			Options: []any{
				"unwrap",
			},
		},
	}
	entries, err := parsePamContent(content)
	require.NoError(t, err)
	assert.Equal(t, expected, entries)
}

func TestIncludePamConfigurationFile(t *testing.T) {
	data, err := os.ReadFile("./testdata/atd")
	require.NoError(t, err)
	content := string(data)

	expected := []*PamLine{
		{
			PamType: "auth",
			Control: "required",
			Module:  "pam_env.so",
			Options: []any{},
		},
		{
			PamType: "@include",
			Control: "common-auth",
			Module:  "",
			Options: []any{},
		},
		{
			PamType: "@include",
			Control: "common-account",
			Module:  "",
			Options: []any{},
		},
		{
			PamType: "@include",
			Control: "common-session-noninteractive",
			Module:  "",
			Options: []any{},
		},
		{
			PamType: "session",
			Control: "required",
			Module:  "pam_limits.so",
			Options: []any{},
		},
	}
	entries, err := parsePamContent(content)
	require.NoError(t, err)
	assert.Equal(t, expected, entries)
}

func TestStripComments(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{"full-line comment", "# this is a comment", ""},
		{"indented full-line comment", "   # indented comment", ""},
		{"trailing comment", "auth required pam_unix.so # use unix auth", "auth required pam_unix.so"},
		{"tab before comment", "auth required pam_unix.so\t# use unix auth", "auth required pam_unix.so"},
		{"hash inside option value", "password required pam_passwdqc.so match=*#*", "password required pam_passwdqc.so match=*#*"},
		{"hash inside option plus trailing comment", "password required pam_passwdqc.so match=*#* # strict", "password required pam_passwdqc.so match=*#*"},
		{"no comment", "auth required pam_unix.so nullok", "auth required pam_unix.so nullok"},
		{"empty line", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, StripComments(tc.line))
		})
	}
}

func TestIsType(t *testing.T) {
	for _, tok := range []string{"auth", "account", "password", "session", "-session", "AUTH", "-Auth"} {
		assert.True(t, IsType(tok), tok)
	}
	for _, tok := range []string{"", "-", "@include", "su", "sshd", "include", "--auth", "authx"} {
		assert.False(t, IsType(tok), tok)
	}
}
