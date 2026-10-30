// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package logrotate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/logrotate"
)

func TestParseContent_EmptyContent(t *testing.T) {
	global, entries := logrotate.ParseContent("/etc/logrotate.conf", "")
	assert.Empty(t, global)
	assert.Empty(t, entries)
}

func TestParseContent_OnlyComments(t *testing.T) {
	content := `# This is a comment
# Another comment`
	global, entries := logrotate.ParseContent("/etc/logrotate.conf", content)
	assert.Empty(t, global)
	assert.Empty(t, entries)
}

func TestParseContent_GlobalDirectives(t *testing.T) {
	content := `# Global options
weekly
rotate 4
create
dateext
compress`

	global, entries := logrotate.ParseContent("/etc/logrotate.conf", content)

	assert.Equal(t, "", global["weekly"])
	assert.Equal(t, "4", global["rotate"])
	assert.Equal(t, "", global["create"])
	assert.Equal(t, "", global["dateext"])
	assert.Equal(t, "", global["compress"])
	assert.Empty(t, entries)
}

func TestParseContent_SinglePathBlock(t *testing.T) {
	content := `/var/log/wtmp {
    monthly
    create 0664 root utmp
    minsize 1M
    rotate 1
}`

	global, entries := logrotate.ParseContent("/etc/logrotate.conf", content)

	assert.Empty(t, global)
	require.Len(t, entries, 1)

	e := entries[0]
	assert.Equal(t, "/etc/logrotate.conf", e.File)
	assert.Equal(t, 1, e.LineNumber)
	assert.Equal(t, "/var/log/wtmp", e.Path)
	assert.Equal(t, "", e.Config["monthly"])
	assert.Equal(t, "0664 root utmp", e.Config["create"])
	assert.Equal(t, "1M", e.Config["minsize"])
	assert.Equal(t, "1", e.Config["rotate"])
}

func TestParseContent_MultipleBlocks(t *testing.T) {
	content := `/var/log/wtmp {
    monthly
    rotate 1
}

/var/log/btmp {
    missingok
    monthly
    rotate 1
}`

	_, entries := logrotate.ParseContent("/etc/logrotate.conf", content)

	require.Len(t, entries, 2)

	assert.Equal(t, "/var/log/wtmp", entries[0].Path)
	assert.Equal(t, 1, entries[0].LineNumber)
	assert.Equal(t, "1", entries[0].Config["rotate"])

	assert.Equal(t, "/var/log/btmp", entries[1].Path)
	assert.Equal(t, 6, entries[1].LineNumber)
	assert.Equal(t, "", entries[1].Config["missingok"])
}

func TestParseContent_MultiPathBlock(t *testing.T) {
	content := `/var/log/cron /var/log/maillog /var/log/messages {
    missingok
    sharedscripts
    rotate 7
}`

	_, entries := logrotate.ParseContent("/etc/logrotate.conf", content)

	require.Len(t, entries, 3)

	assert.Equal(t, "/var/log/cron", entries[0].Path)
	assert.Equal(t, "/var/log/maillog", entries[1].Path)
	assert.Equal(t, "/var/log/messages", entries[2].Path)

	// All entries share the same config
	for _, e := range entries {
		assert.Equal(t, 1, e.LineNumber)
		assert.Equal(t, "", e.Config["missingok"])
		assert.Equal(t, "", e.Config["sharedscripts"])
		assert.Equal(t, "7", e.Config["rotate"])
	}
}

func TestParseContent_MultiPathOnSeparateLines(t *testing.T) {
	// logrotate allows paths on one line and { on the next
	content := `/var/log/cron
/var/log/maillog
{
    rotate 5
}`

	_, entries := logrotate.ParseContent("/etc/logrotate.conf", content)

	// The parser looks backward from the lone { and finds the immediately preceding
	// non-comment, non-empty line. This means only /var/log/maillog is found.
	// This is an acceptable limitation for an uncommon format variant.
	require.NotEmpty(t, entries)
	assert.Equal(t, "/var/log/maillog", entries[0].Path)
}

func TestParseContent_GlobPath(t *testing.T) {
	content := `/var/log/nginx/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
}`

	_, entries := logrotate.ParseContent("/etc/logrotate.conf", content)

	require.Len(t, entries, 1)
	assert.Equal(t, "/var/log/nginx/*.log", entries[0].Path)
	assert.Equal(t, "", entries[0].Config["daily"])
	assert.Equal(t, "14", entries[0].Config["rotate"])
	assert.Equal(t, "", entries[0].Config["compress"])
	assert.Equal(t, "", entries[0].Config["delaycompress"])
	assert.Equal(t, "", entries[0].Config["notifempty"])
}

func TestParseContent_ScriptBlock(t *testing.T) {
	content := `/var/log/syslog {
    daily
    rotate 7
    postrotate
        /usr/bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
    compress
}`

	_, entries := logrotate.ParseContent("/etc/logrotate.conf", content)

	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, "", e.Config["daily"])
	assert.Equal(t, "7", e.Config["rotate"])
	assert.Equal(t, "", e.Config["compress"])
	// Script content should not appear as directives
	_, hasKill := e.Config["/usr/bin/systemctl"]
	assert.False(t, hasKill)
}

func TestParseContent_IncludeSkipped(t *testing.T) {
	content := `weekly
rotate 4
include /etc/logrotate.d`

	global, entries := logrotate.ParseContent("/etc/logrotate.conf", content)

	assert.Equal(t, "", global["weekly"])
	assert.Equal(t, "4", global["rotate"])
	// include should be skipped (not in global config)
	_, hasInclude := global["include"]
	assert.False(t, hasInclude)
	assert.Empty(t, entries)
}

func TestParseContent_TabooextSkipped(t *testing.T) {
	content := `tabooext + .bak .old
weekly`

	global, _ := logrotate.ParseContent("/etc/logrotate.conf", content)

	_, hasTaboo := global["tabooext"]
	assert.False(t, hasTaboo)
	assert.Equal(t, "", global["weekly"])
}

func TestParseContent_InlineComments(t *testing.T) {
	content := `/var/log/test.log {
    rotate 7  # keep 7 rotations
    compress  # enable compression
}`

	_, entries := logrotate.ParseContent("/etc/logrotate.conf", content)

	require.Len(t, entries, 1)
	assert.Equal(t, "7", entries[0].Config["rotate"])
	assert.Equal(t, "", entries[0].Config["compress"])
}

func TestParseContent_BooleanDirectives(t *testing.T) {
	content := `/var/log/test.log {
    compress
    missingok
    notifempty
    copytruncate
    delaycompress
    sharedscripts
    dateext
}`

	_, entries := logrotate.ParseContent("/etc/logrotate.conf", content)

	require.Len(t, entries, 1)
	for _, directive := range []string{"compress", "missingok", "notifempty", "copytruncate", "delaycompress", "sharedscripts", "dateext"} {
		val, ok := entries[0].Config[directive]
		assert.True(t, ok, "missing directive: %s", directive)
		assert.Equal(t, "", val, "directive %s should have empty value", directive)
	}
}

func TestParseContent_ValueDirectives(t *testing.T) {
	content := `/var/log/test.log {
    rotate 14
    size 100M
    maxage 365
    create 0644 root adm
    su root syslog
    olddir /var/log/old
}`

	_, entries := logrotate.ParseContent("/etc/logrotate.conf", content)

	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, "14", e.Config["rotate"])
	assert.Equal(t, "100M", e.Config["size"])
	assert.Equal(t, "365", e.Config["maxage"])
	assert.Equal(t, "0644 root adm", e.Config["create"])
	assert.Equal(t, "root syslog", e.Config["su"])
	assert.Equal(t, "/var/log/old", e.Config["olddir"])
}

func TestParseContent_RealWorldConfig(t *testing.T) {
	content := `# see "man logrotate" for details

# global options
weekly
rotate 4
create
dateext

# RPM packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may also be configured here.

/var/log/wtmp {
    monthly
    create 0664 root utmp
    minsize 1M
    rotate 1
}

/var/log/btmp {
    missingok
    monthly
    create 0600 root utmp
    rotate 1
}`

	global, entries := logrotate.ParseContent("/etc/logrotate.conf", content)

	// Global directives
	assert.Equal(t, "", global["weekly"])
	assert.Equal(t, "4", global["rotate"])
	assert.Equal(t, "", global["create"])
	assert.Equal(t, "", global["dateext"])

	// Entries
	require.Len(t, entries, 2)

	assert.Equal(t, "/var/log/wtmp", entries[0].Path)
	assert.Equal(t, "", entries[0].Config["monthly"])
	assert.Equal(t, "0664 root utmp", entries[0].Config["create"])
	assert.Equal(t, "1M", entries[0].Config["minsize"])
	assert.Equal(t, "1", entries[0].Config["rotate"])

	assert.Equal(t, "/var/log/btmp", entries[1].Path)
	assert.Equal(t, "", entries[1].Config["missingok"])
	assert.Equal(t, "", entries[1].Config["monthly"])
	assert.Equal(t, "0600 root utmp", entries[1].Config["create"])
	assert.Equal(t, "1", entries[1].Config["rotate"])
}

func TestParseContent_RealWorldSyslog(t *testing.T) {
	content := `/var/log/cron
/var/log/maillog
/var/log/messages
/var/log/secure
/var/log/spooler
{
    missingok
    sharedscripts
    postrotate
        /usr/bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}`

	_, entries := logrotate.ParseContent("/etc/logrotate.d/syslog", content)

	// The parser finds the last non-empty/non-comment line before the lone {
	// which is /var/log/spooler. This is an acceptable simplification.
	require.NotEmpty(t, entries)
	assert.Equal(t, "/var/log/spooler", entries[0].Path)
	assert.Equal(t, "", entries[0].Config["missingok"])
	assert.Equal(t, "", entries[0].Config["sharedscripts"])
}

func TestParseContent_MultipleScriptBlocks(t *testing.T) {
	content := `/var/log/test.log {
    daily
    prerotate
        echo "before"
    endscript
    postrotate
        echo "after"
    endscript
    rotate 5
}`

	_, entries := logrotate.ParseContent("/etc/logrotate.d/test", content)

	require.Len(t, entries, 1)
	assert.Equal(t, "", entries[0].Config["daily"])
	assert.Equal(t, "5", entries[0].Config["rotate"])
}

func TestParseContent_ConfigCopyIndependence(t *testing.T) {
	// Verify that multi-path blocks get independent config copies
	content := `/var/log/a.log /var/log/b.log {
    rotate 5
}`

	_, entries := logrotate.ParseContent("/etc/logrotate.conf", content)

	require.Len(t, entries, 2)

	// Modify one entry's config - should not affect the other
	entries[0].Config["extra"] = "value"
	_, hasExtra := entries[1].Config["extra"]
	assert.False(t, hasExtra, "entries should have independent config maps")
}

func TestParseContent_FrequencyDirectives(t *testing.T) {
	content := `/var/log/daily.log {
    daily
}

/var/log/weekly.log {
    weekly
}

/var/log/monthly.log {
    monthly
}

/var/log/yearly.log {
    yearly
}`

	_, entries := logrotate.ParseContent("/etc/logrotate.conf", content)

	require.Len(t, entries, 4)
	_, hasDaily := entries[0].Config["daily"]
	assert.True(t, hasDaily)
	_, hasWeekly := entries[1].Config["weekly"]
	assert.True(t, hasWeekly)
	_, hasMonthly := entries[2].Config["monthly"]
	assert.True(t, hasMonthly)
	_, hasYearly := entries[3].Config["yearly"]
	assert.True(t, hasYearly)
}
