// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func sudoOn() *inventory.Sudo {
	return &inventory.Sudo{Active: true, Executable: "sudo"}
}

func TestBuildSudoCommand_Inactive(t *testing.T) {
	assert.Equal(t, "uname -s", BuildSudoCommand(nil, "uname -s"))
	assert.Equal(t, "uname -s", BuildSudoCommand(&inventory.Sudo{Executable: "sudo"}, "uname -s"))
}

// A plain argv keeps the bare form. The provider issues hundreds of these, and
// the recording/replay system keys on the exact command line, so changing their
// shape would invalidate every recording taken so far.
func TestBuildSudoCommand_PlainArgvIsUnchanged(t *testing.T) {
	for _, cmd := range []string{
		"uname -s",
		"rpm -qa --queryformat '%{NAME}\n'",
		"ls -1 '/etc/ssh'",
		"systemctl show --property=Id -- sshd.service",
		"cat /etc/shadow",
		"find /proc/1/fd -maxdepth 1",
	} {
		assert.Equal(t, "sudo "+cmd, BuildSudoCommand(sudoOn(), cmd), "cmd %q", cmd)
	}
}

// sudo binds to the first word, so a line the shell would have acted on first
// has to go through a shell that is itself under sudo. The cgroups probe is the
// case that was found in the wild: `sudo if [ -r ... ]; then ...` is a syntax
// error, which surfaced as `cgroups` reporting version 0 and no controllers on
// every host scanned with --sudo.
func TestBuildSudoCommand_ShellSyntaxIsWrapped(t *testing.T) {
	for _, tc := range []struct{ name, cmd string }{
		{"leading if", `if [ -r /sys/fs/cgroup/cgroup.controllers ]; then echo V2; else echo NONE; fi`},
		{"leading for", `for f in a b; do echo $f; done`},
		{"leading while", `while read l; do echo $l; done`},
		{"pipeline", `rpm -qa | wc -l`},
		{"and-list", `test -d /x && echo yes`},
		{"semicolon", `cd /tmp; ls`},
		{"redirect out", `apt-get update > /dev/null`},
		{"redirect in", `wc -l < /etc/shadow`},
		{"subshell", `(cd /tmp && ls)`},
		{"substitution", "echo $(hostname)"},
		{"backticks", "echo `hostname`"},
		{"env assignment", `DEBIAN_FRONTEND=noninteractive apt-get update`},
		{"newline", "echo a\necho b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildSudoCommand(sudoOn(), tc.cmd)
			assert.Equal(t, "sudo sh -c "+ShellEscape(tc.cmd), got)
			// the whole original line survives inside the quoted argument
			assert.Contains(t, got, "sh -c ")
		})
	}
}

// A control character inside quotes belongs to the command, not the shell, so
// it must not trigger the wrap -- the file stat helper already hand-wraps
// itself and its recorded command line has to stay byte-identical.
func TestBuildSudoCommand_QuotedOperatorsDoNotWrap(t *testing.T) {
	for _, cmd := range []string{
		`sh -c 'SL=0; test -L "$1" && SL=1' _ /etc/hosts`,
		`awk '{print $1 "|" $2}' /etc/passwd`,
		`grep -E 'a|b' /etc/hosts`,
	} {
		assert.Equal(t, "sudo "+cmd, BuildSudoCommand(sudoOn(), cmd), "cmd %q", cmd)
	}
}

func TestBuildSudoCommand_User(t *testing.T) {
	s := sudoOn()
	s.User = "postgres"
	assert.Equal(t, "sudo -u postgres psql -V", BuildSudoCommand(s, "psql -V"))
	assert.Equal(t, `sudo -u postgres sh -c 'psql -V | head -1'`, BuildSudoCommand(s, "psql -V | head -1"))
}

// An explicit shell always wraps, and the command is quoted -- it was
// concatenated bare before, which broke on the first space.
func TestBuildSudoCommand_ExplicitShellQuotes(t *testing.T) {
	s := sudoOn()
	s.Shell = "bash"
	assert.Equal(t, `sudo bash -c 'if [ -r /x ]; then echo y; fi'`,
		BuildSudoCommand(s, "if [ -r /x ]; then echo y; fi"))
	assert.Equal(t, `sudo bash -c 'uname -s'`, BuildSudoCommand(s, "uname -s"))
}

// Unbalanced quoting is not an argv we can reason about; hand it to a shell
// rather than giving sudo half a word.
func TestBuildSudoCommand_UnbalancedQuotes(t *testing.T) {
	got := BuildSudoCommand(sudoOn(), `echo 'oops`)
	assert.Equal(t, "sudo sh -c "+ShellEscape(`echo 'oops`), got)
}
