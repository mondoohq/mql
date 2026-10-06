// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cat

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/unicode"
)

// decodeCommand recovers the script from a `-EncodedCommand` command line.
func decodeCommand(t *testing.T, command string) string {
	t.Helper()

	fields := strings.Fields(command)
	require.Len(t, fields, 4, "expected an encoded command line, got %q", command)
	assert.Equal(t, "-EncodedCommand", fields[2])

	raw, err := base64.StdEncoding.DecodeString(fields[3])
	require.NoError(t, err)

	script, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(raw)
	require.NoError(t, err)
	return string(script)
}

func TestScriptsQuoteTheFileName(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		expected string
	}{
		{
			name:     "plain path",
			file:     `C:\Windows\System32\drivers\etc\hosts`,
			expected: `'C:\Windows\System32\drivers\etc\hosts'`,
		},
		{
			name:     "path with spaces",
			file:     `C:\Program Files\New Text Document.txt`,
			expected: `'C:\Program Files\New Text Document.txt'`,
		},
		{
			// a Windows file name may contain a single quote, and the
			// command line layer used to need its own escaping on top
			name:     "path with a quote",
			file:     `C:\tmp\od'd.txt`,
			expected: `'C:\tmp\od''d.txt'`,
		},
		{
			name:     "path with a double quote",
			file:     `C:\tmp\a"b.txt`,
			expected: `'C:\tmp\a"b.txt'`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content := decodeCommand(t, openScript(test.file))
			assert.Contains(t, content, "Test-Path -LiteralPath "+test.expected+" -PathType Container")
			assert.Contains(t, content, "Get-Content -LiteralPath "+test.expected)

			item := decodeCommand(t, getItemScript(test.file))
			assert.Contains(t, item, "Get-Item -LiteralPath "+test.expected+" | ConvertTo-JSON")

			list := decodeCommand(t, listDirScript(test.file))
			assert.Contains(t, list, "Get-ChildItem -LiteralPath "+test.expected+" -Force")
		})
	}
}
