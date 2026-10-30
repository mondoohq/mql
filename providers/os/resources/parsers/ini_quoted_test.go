// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package parsers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func iniGroup(t *testing.T, ini *Ini, group string) map[string]any {
	t.Helper()
	g, ok := ini.Fields[group].(map[string]any)
	assert.True(t, ok, "group %q should exist", group)
	return g
}

// A "#" inside a quoted value is part of the value, not the start of a
// comment. Cutting the line there truncated the value and left the quote
// unterminated.
func TestParseIniHashInsideQuotedValue(t *testing.T) {
	raw := `[main]
proxy_password = "p@ss#word"
single = 'we#rd'
tag = "a#b#c"
`
	g := iniGroup(t, ParseIni(raw, "="), "main")

	assert.Equal(t, `"p@ss#word"`, g["proxy_password"])
	assert.Equal(t, `'we#rd'`, g["single"])
	assert.Equal(t, `"a#b#c"`, g["tag"])
}

// Inline comments on unquoted values keep working; callers have always relied
// on that.
func TestParseIniInlineCommentsStillStripped(t *testing.T) {
	raw := `[main]
gpgcheck = 1 # verify signatures
installonly_limit = 3   # keep three kernels
bare = value#nospace
`
	g := iniGroup(t, ParseIni(raw, "="), "main")

	assert.Equal(t, "1", g["gpgcheck"])
	assert.Equal(t, "3", g["installonly_limit"])
	assert.Equal(t, "value", g["bare"])
}

// A comment following a quoted value is still a comment.
func TestParseIniCommentAfterQuotedValue(t *testing.T) {
	raw := `[main]
key = "quoted#value" # trailing comment
`
	g := iniGroup(t, ParseIni(raw, "="), "main")
	assert.Equal(t, `"quoted#value"`, g["key"])
}

// Whole-line comments and section headers are unaffected.
func TestParseIniLineCommentsUnaffected(t *testing.T) {
	raw := `# a leading comment
[main]
# another comment
key = value
`
	ini := ParseIni(raw, "=")
	g := iniGroup(t, ini, "main")
	assert.Equal(t, "value", g["key"])
	assert.Len(t, g, 1)
}

func TestUnquotedHashIndex(t *testing.T) {
	tests := []struct {
		line string
		want int
	}{
		{`no hash here`, -1},
		{`# leading`, 0},
		{`key = value # comment`, 12},
		{`key = "a#b"`, -1},
		{`key = 'a#b'`, -1},
		{`key = "a#b" # after`, 12},
		{`key = "unterminated#`, -1},
		{``, -1},
	}
	for _, tc := range tests {
		t.Run(tc.line, func(t *testing.T) {
			assert.Equal(t, tc.want, unquotedHashIndex(tc.line))
		})
	}
}
