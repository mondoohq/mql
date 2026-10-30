// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sudoers_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/sudoers"
)

// User specs from /etc/sudoers.d on Ubuntu 16.04 to 26.04 hosts (the
// Cmnd_Alias is renamed, the parser does not resolve aliases). The expected
// values follow `sudo -l -U <user>` on those hosts (sudo 1.9.15p5 and
// sudo-rs 0.2.13):
//
//	(root) NOPASSWD: /bin/cat
//	(ALL : ALL) NOPASSWD: /bin/date, PASSWD: /bin/hostname
//	(root, daemon) NOPASSWD: /bin/ls, /usr/bin/id
//	(mqlt_locked : mqlg2) /usr/bin/whoami
const cmndSpecSudoers = `User_Alias MQLADMINS = mqlt_bash, mqlt_locked
Cmnd_Alias LISTING = /bin/ls, /usr/bin/id
Runas_Alias MQLRUNAS = root, daemon
Defaults:MQLADMINS !lecture, timestamp_timeout=5
MQLADMINS ALL=(MQLRUNAS) NOPASSWD: LISTING
mqlt_bash ALL = (root) NOPASSWD: /bin/cat
mqlt_bash ALL=(ALL:ALL) NOPASSWD: /bin/date, PASSWD: /bin/hostname
%mqlg1 MQLHOSTS=(root) SETENV: NOEXEC: /usr/bin/env, \
    /usr/bin/printenv
mqlt_locked ALL=(:mqlg2) /usr/bin/whoami
`

func TestParseUserSpecs_CmndSpecs(t *testing.T) {
	specs := sudoers.ParseUserSpecs("/etc/sudoers.d/mqltest", cmndSpecSudoers)
	require.Len(t, specs, 5)

	alias := specs[0]
	assert.Equal(t, []string{"MQLADMINS"}, alias.Users)
	assert.Equal(t, []string{"MQLRUNAS"}, alias.RunasUsers)
	assert.Equal(t, []string{"NOPASSWD"}, alias.Tags)
	assert.Equal(t, []string{"LISTING"}, alias.Commands)

	// Spaces around `=` must not lose the runas spec.
	spaced := specs[1]
	assert.Equal(t, 6, spaced.LineNumber)
	assert.Equal(t, []string{"mqlt_bash"}, spaced.Users)
	assert.Equal(t, []string{"ALL"}, spaced.Hosts)
	assert.Equal(t, []string{"root"}, spaced.RunasUsers)
	assert.Nil(t, spaced.RunasGroups)
	assert.Equal(t, []string{"NOPASSWD"}, spaced.Tags)
	assert.Equal(t, []string{"/bin/cat"}, spaced.Commands)

	// A later tag must not drop the commands before it.
	tagged := specs[2]
	assert.Equal(t, []string{"ALL"}, tagged.RunasUsers)
	assert.Equal(t, []string{"ALL"}, tagged.RunasGroups)
	assert.Equal(t, []string{"NOPASSWD", "PASSWD"}, tagged.Tags)
	assert.Equal(t, []string{"/bin/date", "/bin/hostname"}, tagged.Commands)

	group := specs[3]
	assert.Equal(t, []string{"%mqlg1"}, group.Users)
	assert.Equal(t, []string{"MQLHOSTS"}, group.Hosts)
	assert.Equal(t, []string{"root"}, group.RunasUsers)
	assert.Equal(t, []string{"SETENV", "NOEXEC"}, group.Tags)
	assert.Equal(t, []string{"/usr/bin/env", "/usr/bin/printenv"}, group.Commands)

	groupOnly := specs[4]
	assert.Equal(t, []string{}, groupOnly.RunasUsers)
	assert.Equal(t, []string{"mqlg2"}, groupOnly.RunasGroups)
	assert.Empty(t, groupOnly.Tags)
	assert.Equal(t, []string{"/usr/bin/whoami"}, groupOnly.Commands)
}

func TestParseLine_PerCommandRunas(t *testing.T) {
	// A runas spec on a later command applies from there on, and its
	// comma-separated list is not split into commands.
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(
		"op ALL = (root) /bin/ls, (operator, daemon : wheel) NOPASSWD: /bin/kill, /bin/ps"))
	require.NotNil(t, parsed)
	assert.Equal(t, []string{"root", "operator", "daemon"}, parsed.RunasUsers)
	assert.Equal(t, []string{"wheel"}, parsed.RunasGroups)
	assert.Equal(t, []string{"NOPASSWD"}, parsed.Tags)
	assert.Equal(t, []string{"/bin/ls", "/bin/kill", "/bin/ps"}, parsed.Commands)
}

func TestParseLine_TagWordInsideCommand(t *testing.T) {
	// A tag name followed by a colon inside a command's arguments is part of
	// the command, not a tag.
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(`bob ALL=(root) /usr/bin/printf "MAIL: %s", /bin/true`))
	require.NotNil(t, parsed)
	assert.Empty(t, parsed.Tags)
	assert.Equal(t, []string{`/usr/bin/printf "MAIL: %s"`, "/bin/true"}, parsed.Commands)
}

func TestParseLine_EqualsInsideCommand(t *testing.T) {
	// Without a runas spec, a `=(` inside the command must not be read as one.
	parsed := sudoers.ToParsedLine(sudoers.ParseLine("bob ALL=/usr/bin/env FOO=(x) /bin/true"))
	require.NotNil(t, parsed)
	assert.Equal(t, []string{"ALL"}, parsed.Hosts)
	assert.Nil(t, parsed.RunasUsers)
	assert.Equal(t, []string{"/usr/bin/env FOO=(x) /bin/true"}, parsed.Commands)
}
