// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package crontab

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCrontab_SystemCrontab(t *testing.T) {
	content := `# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
`

	entries, err := ParseCrontab(strings.NewReader(content), true)
	require.NoError(t, err)
	require.Len(t, entries, 4)

	// Check first entry
	assert.Equal(t, "17", entries[0].Minute)
	assert.Equal(t, "*", entries[0].Hour)
	assert.Equal(t, "*", entries[0].DayOfMonth)
	assert.Equal(t, "*", entries[0].Month)
	assert.Equal(t, "*", entries[0].DayOfWeek)
	assert.Equal(t, "root", entries[0].User)
	assert.Equal(t, "cd / && run-parts --report /etc/cron.hourly", entries[0].Command)

	// Check weekly entry
	assert.Equal(t, "47", entries[2].Minute)
	assert.Equal(t, "6", entries[2].Hour)
	assert.Equal(t, "*", entries[2].DayOfMonth)
	assert.Equal(t, "*", entries[2].Month)
	assert.Equal(t, "7", entries[2].DayOfWeek)
	assert.Equal(t, "root", entries[2].User)
}

func TestParseCrontab_UserCrontab(t *testing.T) {
	content := `# Edit this file to introduce tasks to be run by cron.
# m h  dom mon dow   command
*/5 * * * * /usr/bin/backup.sh
0 2 * * * /usr/bin/nightly-job.sh --verbose
`

	entries, err := ParseCrontab(strings.NewReader(content), false)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	// Check first entry (every 5 minutes)
	assert.Equal(t, "*/5", entries[0].Minute)
	assert.Equal(t, "*", entries[0].Hour)
	assert.Equal(t, "*", entries[0].DayOfMonth)
	assert.Equal(t, "*", entries[0].Month)
	assert.Equal(t, "*", entries[0].DayOfWeek)
	assert.Equal(t, "", entries[0].User) // User crontabs don't have user field
	assert.Equal(t, "/usr/bin/backup.sh", entries[0].Command)

	// Check second entry
	assert.Equal(t, "0", entries[1].Minute)
	assert.Equal(t, "2", entries[1].Hour)
	assert.Equal(t, "/usr/bin/nightly-job.sh --verbose", entries[1].Command)
}

func TestParseCrontab_SpecialStrings(t *testing.T) {
	content := `@reboot root /usr/bin/startup.sh
@hourly root /usr/bin/hourly-task.sh
@daily root /usr/bin/daily-backup.sh
@weekly root /usr/bin/weekly-report.sh
@monthly root /usr/bin/monthly-cleanup.sh
@yearly root /usr/bin/yearly-archive.sh
`

	entries, err := ParseCrontab(strings.NewReader(content), true)
	require.NoError(t, err)
	require.Len(t, entries, 6)

	// @reboot
	assert.Equal(t, "@reboot", entries[0].Minute)
	assert.Equal(t, "root", entries[0].User)
	assert.Equal(t, "/usr/bin/startup.sh", entries[0].Command)

	// @hourly expands to 0 * * * *
	assert.Equal(t, "0", entries[1].Minute)
	assert.Equal(t, "*", entries[1].Hour)
	assert.Equal(t, "*", entries[1].DayOfMonth)
	assert.Equal(t, "*", entries[1].Month)
	assert.Equal(t, "*", entries[1].DayOfWeek)

	// @daily expands to 0 0 * * *
	assert.Equal(t, "0", entries[2].Minute)
	assert.Equal(t, "0", entries[2].Hour)
	assert.Equal(t, "*", entries[2].DayOfMonth)
	assert.Equal(t, "*", entries[2].Month)
	assert.Equal(t, "*", entries[2].DayOfWeek)

	// @weekly expands to 0 0 * * 0
	assert.Equal(t, "0", entries[3].Minute)
	assert.Equal(t, "0", entries[3].Hour)
	assert.Equal(t, "*", entries[3].DayOfMonth)
	assert.Equal(t, "*", entries[3].Month)
	assert.Equal(t, "0", entries[3].DayOfWeek)

	// @monthly expands to 0 0 1 * *
	assert.Equal(t, "0", entries[4].Minute)
	assert.Equal(t, "0", entries[4].Hour)
	assert.Equal(t, "1", entries[4].DayOfMonth)
	assert.Equal(t, "*", entries[4].Month)
	assert.Equal(t, "*", entries[4].DayOfWeek)

	// @yearly expands to 0 0 1 1 *
	assert.Equal(t, "0", entries[5].Minute)
	assert.Equal(t, "0", entries[5].Hour)
	assert.Equal(t, "1", entries[5].DayOfMonth)
	assert.Equal(t, "1", entries[5].Month)
	assert.Equal(t, "*", entries[5].DayOfWeek)
}

func TestParseCrontab_SkipsEnvVars(t *testing.T) {
	content := `SHELL=/bin/bash
MAILTO=admin@example.com
PATH=/usr/local/bin:/usr/bin:/bin

0 * * * * root /usr/bin/task.sh
`

	entries, err := ParseCrontab(strings.NewReader(content), true)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.Equal(t, "0", entries[0].Minute)
	assert.Equal(t, "root", entries[0].User)
	assert.Equal(t, "/usr/bin/task.sh", entries[0].Command)
}

func TestParseCrontab_EmptyFile(t *testing.T) {
	content := `# This is an empty crontab
# No entries here
`

	entries, err := ParseCrontab(strings.NewReader(content), true)
	require.NoError(t, err)
	require.Len(t, entries, 0)
}

func TestParseCrontab_LineNumbers(t *testing.T) {
	content := `# Comment line 1
# Comment line 2

0 * * * * root /usr/bin/task1.sh
# Another comment
30 2 * * * root /usr/bin/task2.sh
`

	entries, err := ParseCrontab(strings.NewReader(content), true)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	assert.Equal(t, 4, entries[0].LineNumber)
	assert.Equal(t, 6, entries[1].LineNumber)
}

func TestParseCrontab_PreservesCommandWhitespace(t *testing.T) {
	// Commands with intentional multiple spaces should be preserved
	content := `0 * * * * root echo "hello    world"
@reboot root /usr/bin/cmd  --arg1  --arg2
`

	entries, err := ParseCrontab(strings.NewReader(content), true)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	// Multiple spaces in the command should be preserved
	assert.Equal(t, `echo "hello    world"`, entries[0].Command)
	assert.Equal(t, "/usr/bin/cmd  --arg1  --arg2", entries[1].Command)
}

func TestParseCrontab_SpecialStringsUserCrontab(t *testing.T) {
	// User crontabs with special strings (no user field)
	content := `@reboot /usr/bin/startup.sh  --init
@daily /usr/bin/backup.sh
`

	entries, err := ParseCrontab(strings.NewReader(content), false)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	assert.Equal(t, "@reboot", entries[0].Minute)
	assert.Equal(t, "", entries[0].User)
	assert.Equal(t, "/usr/bin/startup.sh  --init", entries[0].Command)

	assert.Equal(t, "0", entries[1].Minute)
	assert.Equal(t, "0", entries[1].Hour)
	assert.Equal(t, "/usr/bin/backup.sh", entries[1].Command)
}

// SLES 15 SP7 and Leap 15.6 ship this /etc/crontab. cronie reads the leading
// "-" as "do not log this command to syslog", so run-crons runs every 15
// minutes; the minute field is */15, not -*/15.
const sles15Crontab = `SHELL=/bin/sh
PATH=/usr/bin:/usr/sbin:/sbin:/bin:/usr/lib/news/bin
MAILTO=root
#
# check scripts in cron.hourly, cron.daily, cron.weekly, and cron.monthly

# Example of job definition:
# *  *  *  *  * user-name command to be executed
-*/15 * * * *   root  test -x /usr/lib/cron/run-crons && /usr/lib/cron/run-crons >/dev/null 2>&1
`

func TestParseCronieCrontab_NoLogPrefix(t *testing.T) {
	entries, err := ParseCronieCrontab(strings.NewReader(sles15Crontab), true, true)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "*/15", entries[0].Minute)
	assert.Equal(t, "*", entries[0].Hour)
	assert.Equal(t, "root", entries[0].User)
	assert.Equal(t, "test -x /usr/lib/cron/run-crons && /usr/lib/cron/run-crons >/dev/null 2>&1", entries[0].Command)
	assert.Equal(t, 9, entries[0].LineNumber)

	// the prefix also goes in front of a special time string
	entries, err = ParseCronieCrontab(strings.NewReader("-@daily root /usr/bin/true\n"), true, true)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "0", entries[0].Minute)
	assert.Equal(t, "0", entries[0].Hour)
	assert.Equal(t, "/usr/bin/true", entries[0].Command)
}

// cronie refuses the prefix in an unprivileged user's crontab ("Only
// privileged user can disable logging") and does not run that line.
func TestParseCronieCrontab_UnprivilegedRefusesNoLogPrefix(t *testing.T) {
	content := "-*/15 * * * * /usr/bin/true quiet\n*/5 * * * * /usr/bin/true loud\n"
	entries, err := ParseCronieCrontab(strings.NewReader(content), false, false)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "/usr/bin/true loud", entries[0].Command)
}

// Other cron implementations have no such prefix; their reading is unchanged.
func TestParseCrontab_KeepsDashOutsideCronie(t *testing.T) {
	entries, err := ParseCrontab(strings.NewReader(sles15Crontab), true)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "-*/15", entries[0].Minute)
}
