// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package logrotate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// logrotate accepts the log path and its opening brace on separate lines. The
// path line used to be recorded as a global directive before the brace handler
// claimed it, leaving the log path in globalConfig as a directive nobody wrote.
func TestParseContentLoneBraceDoesNotLeakPathIntoGlobalConfig(t *testing.T) {
	content := `weekly
rotate 4

/var/log/lonebrace.log
{
    daily
    rotate 9
    compress
}

/var/log/sameline.log {
    monthly
}
`

	global, entries := ParseContent("/etc/logrotate.conf", content)

	assert.Equal(t, map[string]string{"weekly": "", "rotate": "4"}, global,
		"only the real global directives belong in globalConfig")
	assert.NotContains(t, global, "/var/log/lonebrace.log",
		"the lone-brace block's path must not appear as a global directive")

	assert.Len(t, entries, 2)
	assert.Equal(t, "/var/log/lonebrace.log", entries[0].Path)
	assert.Equal(t, "9", entries[0].Config["rotate"], "the block still parses")
	assert.Equal(t, "/var/log/sameline.log", entries[1].Path)
}

// Several paths on the line before a lone brace: none of them may leak, and
// the block must still claim all of them.
func TestParseContentLoneBraceMultiplePaths(t *testing.T) {
	content := `su root adm

/var/log/a.log /var/log/b.log
{
    rotate 3
}
`

	global, entries := ParseContent("/etc/logrotate.conf", content)

	assert.Equal(t, map[string]string{"su": "root adm"}, global)
	assert.NotContains(t, global, "/var/log/a.log")

	// One entry per path in the block.
	assert.Len(t, entries, 2)
	assert.Equal(t, "/var/log/a.log", entries[0].Path)
	assert.Equal(t, "/var/log/b.log", entries[1].Path)
}

// A comment or blank line between the paths and the brace is still the same
// block, so the path must not leak there either.
func TestParseContentLoneBraceWithInterveningComment(t *testing.T) {
	content := `compress

/var/log/commented.log
# rotate this one aggressively

{
    rotate 1
}
`

	global, entries := ParseContent("/etc/logrotate.conf", content)

	assert.Equal(t, map[string]string{"compress": ""}, global)
	assert.NotContains(t, global, "/var/log/commented.log")

	assert.Len(t, entries, 1)
	assert.Equal(t, "/var/log/commented.log", entries[0].Path)
}

// A real global directive that merely precedes a block on a later line must
// still be recorded.
func TestParseContentGlobalsBeforeBlocksSurvive(t *testing.T) {
	content := `dateext
maxage 30

/var/log/keep.log {
    rotate 5
}
`

	global, entries := ParseContent("/etc/logrotate.conf", content)

	assert.Equal(t, map[string]string{"dateext": "", "maxage": "30"}, global)
	assert.Len(t, entries, 1)
}
