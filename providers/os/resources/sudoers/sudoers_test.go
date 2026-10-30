// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sudoers_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/sudoers"
)

func TestParseLine_BasicUserSpec(t *testing.T) {
	line := "root ALL=(ALL:ALL) ALL"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, "user_spec", parsed.EntryType)
	assert.Equal(t, []string{"root"}, parsed.Users)
	assert.Equal(t, []string{"ALL"}, parsed.Hosts)
	assert.Equal(t, []string{"ALL"}, parsed.RunasUsers)
	assert.Equal(t, []string{"ALL"}, parsed.RunasGroups)
	assert.Equal(t, []string{"ALL"}, parsed.Commands)
}

func TestParseLine_NoRunasAllCommands(t *testing.T) {
	// A user spec with no runas list and no whitespace around `=`. This is
	// valid sudoers (`user host=command`) and must not be dropped.
	line := "root ALL=ALL"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, "user_spec", parsed.EntryType)
	assert.Equal(t, []string{"root"}, parsed.Users)
	assert.Equal(t, []string{"ALL"}, parsed.Hosts)
	assert.Empty(t, parsed.RunasUsers)
	assert.Equal(t, []string{"ALL"}, parsed.Commands)
}

func TestParseLine_NoRunasSpecificCommand(t *testing.T) {
	// No runas list, host followed directly by `=` and a specific command.
	line := "bob server1=/usr/bin/ls"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, "user_spec", parsed.EntryType)
	assert.Equal(t, []string{"bob"}, parsed.Users)
	assert.Equal(t, []string{"server1"}, parsed.Hosts)
	assert.Empty(t, parsed.RunasUsers)
	assert.Equal(t, []string{"/usr/bin/ls"}, parsed.Commands)
}

func TestParseLine_NoRunasWithTag(t *testing.T) {
	// No runas list, but a NOPASSWD tag attached after `host=`.
	line := "john ALL=NOPASSWD: /usr/bin/systemctl"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, "user_spec", parsed.EntryType)
	assert.Equal(t, []string{"john"}, parsed.Users)
	assert.Equal(t, []string{"ALL"}, parsed.Hosts)
	assert.Empty(t, parsed.RunasUsers)
	assert.Equal(t, []string{"NOPASSWD"}, parsed.Tags)
	assert.Equal(t, []string{"/usr/bin/systemctl"}, parsed.Commands)
}

func TestParseLine_GroupSpec(t *testing.T) {
	line := "%sudo ALL=(ALL:ALL) ALL"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, "user_spec", parsed.EntryType)
	assert.Equal(t, []string{"%sudo"}, parsed.Users)
	assert.Equal(t, []string{"ALL"}, parsed.Hosts)
	assert.Equal(t, []string{"ALL"}, parsed.RunasUsers)
	assert.Equal(t, []string{"ALL"}, parsed.RunasGroups)
}

func TestParseLine_NoPassword(t *testing.T) {
	line := "john ALL=(ALL) NOPASSWD: ALL"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, "user_spec", parsed.EntryType)
	assert.Equal(t, []string{"john"}, parsed.Users)
	assert.Equal(t, []string{"ALL"}, parsed.Hosts)
	assert.Equal(t, []string{"ALL"}, parsed.RunasUsers)
	assert.Empty(t, parsed.RunasGroups)
	assert.Equal(t, []string{"NOPASSWD"}, parsed.Tags)
	assert.Equal(t, []string{"ALL"}, parsed.Commands)
}

func TestParseLine_SpecificCommands(t *testing.T) {
	line := "jane ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/systemctl reload nginx"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, "user_spec", parsed.EntryType)
	assert.Equal(t, []string{"jane"}, parsed.Users)
	assert.Equal(t, []string{"ALL"}, parsed.Hosts)
	assert.Equal(t, []string{"root"}, parsed.RunasUsers)
	assert.Equal(t, []string{"NOPASSWD"}, parsed.Tags)
	assert.Equal(t, []string{
		"/usr/bin/systemctl restart nginx",
		"/usr/bin/systemctl reload nginx",
	}, parsed.Commands)
}

func TestParseLine_MultipleTags(t *testing.T) {
	line := "bob ALL=(ALL) NOPASSWD: SETENV: /usr/bin/docker"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, "user_spec", parsed.EntryType)
	assert.Equal(t, []string{"bob"}, parsed.Users)
	assert.Equal(t, []string{"NOPASSWD", "SETENV"}, parsed.Tags)
	assert.Equal(t, []string{"/usr/bin/docker"}, parsed.Commands)
}

func TestParseLine_MultipleUsers(t *testing.T) {
	line := "john, jane, bob ALL=(ALL) ALL"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, "user_spec", parsed.EntryType)
	assert.Equal(t, []string{"john", "jane", "bob"}, parsed.Users)
	assert.Equal(t, []string{"ALL"}, parsed.Hosts)
}

func TestParseLine_SpecificHost(t *testing.T) {
	line := "admin webserver01, webserver02=(ALL) ALL"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, "user_spec", parsed.EntryType)
	assert.Equal(t, []string{"admin"}, parsed.Users)
	assert.Equal(t, []string{"webserver01", "webserver02"}, parsed.Hosts)
}

func TestParseLine_RunAsGroupOnly(t *testing.T) {
	line := "developer ALL=(ALL) ALL"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, "user_spec", parsed.EntryType)
	assert.Equal(t, []string{"developer"}, parsed.Users)
	assert.Equal(t, []string{"ALL"}, parsed.RunasUsers)
	assert.Empty(t, parsed.RunasGroups)
}

func TestParseLine_ComplexCommand(t *testing.T) {
	line := "backup ALL=(root) NOPASSWD: /usr/bin/rsync -av /data/ /backup/"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, "user_spec", parsed.EntryType)
	assert.Equal(t, []string{"backup"}, parsed.Users)
	assert.Equal(t, []string{"root"}, parsed.RunasUsers)
	assert.Equal(t, []string{"NOPASSWD"}, parsed.Tags)
	assert.Equal(t, 1, len(parsed.Commands))
	assert.Contains(t, parsed.Commands[0], "rsync")
}

func TestParseLine_EmptyLine(t *testing.T) {
	line := ""
	parsed := sudoers.ParseLine(line)
	assert.Nil(t, parsed)
}

func TestParseLine_CommentLine(t *testing.T) {
	line := "# This is a comment"
	parsed := sudoers.ParseLine(line)
	assert.Nil(t, parsed)
}

func TestParseLine_NoExecTag(t *testing.T) {
	line := "test ALL=(ALL) NOEXEC: /usr/bin/vim"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, []string{"NOEXEC"}, parsed.Tags)
}

func TestParseLine_LogInputOutputTags(t *testing.T) {
	line := "admin ALL=(ALL) LOG_INPUT: LOG_OUTPUT: /usr/bin/bash"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, []string{"LOG_INPUT", "LOG_OUTPUT"}, parsed.Tags)
}

func TestParseLine_MailTag(t *testing.T) {
	line := "user ALL=(ALL) MAIL: /usr/bin/command"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, []string{"MAIL"}, parsed.Tags)
}

func TestParseLine_NegatedUser(t *testing.T) {
	line := "!root ALL=(ALL) ALL"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, []string{"!root"}, parsed.Users)
}

func TestParseLine_NegatedCommand(t *testing.T) {
	line := "john ALL=(ALL) ALL, !/usr/bin/su"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, 2, len(parsed.Commands))
	assert.Contains(t, parsed.Commands, "ALL")
	assert.Contains(t, parsed.Commands, "!/usr/bin/su")
}

func TestParseLine_WildcardCommand(t *testing.T) {
	line := "john ALL=(ALL) /usr/bin/*"
	parsed := sudoers.ToParsedLine(sudoers.ParseLine(line))

	require.NotNil(t, parsed)
	assert.Equal(t, []string{"/usr/bin/*"}, parsed.Commands)
}

func TestParseDefaultsLine_Global(t *testing.T) {
	scope, target, parameter, value, operation, negated := sudoers.ParseDefaultsLine("Defaults env_reset")

	assert.Equal(t, "global", scope)
	assert.Equal(t, "", target)
	assert.Equal(t, "env_reset", parameter)
	assert.Equal(t, "", value)
	assert.Equal(t, "", operation)
	assert.False(t, negated)
}

func TestParseDefaultsLine_WithValue(t *testing.T) {
	scope, target, parameter, value, operation, negated := sudoers.ParseDefaultsLine("Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"")

	assert.Equal(t, "global", scope)
	assert.Equal(t, "", target)
	assert.Equal(t, "secure_path", parameter)
	assert.Equal(t, "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", value)
	assert.Equal(t, "=", operation)
	assert.False(t, negated)
}

func TestParseDefaultsLine_UserScope(t *testing.T) {
	scope, target, parameter, value, operation, negated := sudoers.ParseDefaultsLine("Defaults:john !requiretty")

	assert.Equal(t, "user", scope)
	assert.Equal(t, "john", target)
	assert.Equal(t, "requiretty", parameter)
	assert.Equal(t, "", value)
	assert.Equal(t, "", operation)
	assert.True(t, negated)
}

func TestParseDefaultsLine_HostScope(t *testing.T) {
	scope, target, parameter, value, operation, negated := sudoers.ParseDefaultsLine("Defaults@webserver env_keep += \"FOO\"")

	assert.Equal(t, "host", scope)
	assert.Equal(t, "webserver", target)
	assert.Equal(t, "env_keep", parameter)
	assert.Equal(t, "FOO", value)
	assert.Equal(t, "+=", operation)
	assert.False(t, negated)
}

func TestParseDefaultsLine_RunasScope(t *testing.T) {
	scope, target, parameter, value, operation, negated := sudoers.ParseDefaultsLine("Defaults>root env_reset")

	assert.Equal(t, "runas", scope)
	assert.Equal(t, "root", target)
	assert.Equal(t, "env_reset", parameter)
	assert.Equal(t, "", value)
	assert.Equal(t, "", operation)
	assert.False(t, negated)
}

func TestParseDefaultsLine_CommandScope(t *testing.T) {
	scope, target, parameter, value, operation, negated := sudoers.ParseDefaultsLine("Defaults!/usr/bin/su !authenticate")

	assert.Equal(t, "command", scope)
	assert.Equal(t, "/usr/bin/su", target)
	assert.Equal(t, "authenticate", parameter)
	assert.Equal(t, "", value)
	assert.Equal(t, "", operation)
	assert.True(t, negated)
}

func TestParseDefaultsLine_NegatedGlobal(t *testing.T) {
	// "!" after whitespace negates a global parameter; it is not a command scope.
	for _, line := range []string{"Defaults !authenticate", "Defaults\t!visiblepw"} {
		scope, target, parameter, _, _, negated := sudoers.ParseDefaultsLine(line)

		assert.Equal(t, "global", scope, line)
		assert.Equal(t, "", target, line)
		assert.NotEmpty(t, parameter, line)
		assert.True(t, negated, line)
	}
}

func TestSmartSplit_BasicSplit(t *testing.T) {
	result := sudoers.SmartSplit("user host command")
	assert.Equal(t, []string{"user", "host", "command"}, result)
}

func TestSmartSplit_WithQuotes(t *testing.T) {
	result := sudoers.SmartSplit(`user host "command with spaces"`)
	assert.Equal(t, []string{"user", "host", `"command with spaces"`}, result)
}

func TestSmartSplit_WithEscapes(t *testing.T) {
	result := sudoers.SmartSplit(`user host command\ with\ escape`)
	assert.Equal(t, []string{"user", "host", `command\ with\ escape`}, result)
}

func TestSplitCommands_SingleCommand(t *testing.T) {
	result := sudoers.SplitCommands("/usr/bin/systemctl restart nginx")
	assert.Equal(t, []string{"/usr/bin/systemctl restart nginx"}, result)
}

func TestSplitCommands_MultipleCommands(t *testing.T) {
	result := sudoers.SplitCommands("/usr/bin/systemctl restart nginx, /usr/bin/systemctl reload nginx")
	assert.Equal(t, []string{
		"/usr/bin/systemctl restart nginx",
		"/usr/bin/systemctl reload nginx",
	}, result)
}

func TestSplitCommands_WithQuotedComma(t *testing.T) {
	result := sudoers.SplitCommands(`/usr/bin/echo "hello, world", /usr/bin/echo goodbye`)
	assert.Equal(t, []string{
		`/usr/bin/echo "hello, world"`,
		"/usr/bin/echo goodbye",
	}, result)
}

func TestSplitAndTrim_BasicSplit(t *testing.T) {
	result := sudoers.SplitAndTrim("john, jane, bob", ",")
	assert.Equal(t, []string{"john", "jane", "bob"}, result)
}

func TestSplitAndTrim_WithExtraSpaces(t *testing.T) {
	result := sudoers.SplitAndTrim("  john  ,  jane  ,  bob  ", ",")
	assert.Equal(t, []string{"john", "jane", "bob"}, result)
}

func TestSplitAndTrim_EmptyString(t *testing.T) {
	result := sudoers.SplitAndTrim("", ",")
	assert.Empty(t, result)
}

func TestSplitAndTrim_SingleItem(t *testing.T) {
	result := sudoers.SplitAndTrim("john", ",")
	assert.Equal(t, []string{"john"}, result)
}

func TestIncludeRegex_AtInclude(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{"@include /etc/sudoers.local", "/etc/sudoers.local"},
		{"@include /path/to/file", "/path/to/file"},
		{"@include   /path/with/spaces  ", "/path/with/spaces"},
	}

	for _, tt := range tests {
		matches := sudoers.IncludeRegex.FindStringSubmatch(tt.line)
		require.NotNil(t, matches, "line: %s", tt.line)
		assert.Equal(t, tt.expected, strings.TrimSpace(matches[1]))
	}
}

func TestIncludeRegex_HashInclude(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{"#include /etc/sudoers.local", "/etc/sudoers.local"},
		{"#include /path/to/file", "/path/to/file"},
	}

	for _, tt := range tests {
		matches := sudoers.IncludeRegex.FindStringSubmatch(tt.line)
		require.NotNil(t, matches, "line: %s", tt.line)
		assert.Equal(t, tt.expected, strings.TrimSpace(matches[1]))
	}
}

func TestIncludedirRegex_AtIncludedir(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{"@includedir /etc/sudoers.d", "/etc/sudoers.d"},
		{"@includedir /path/to/dir", "/path/to/dir"},
		{"@includedir   /path/with/spaces  ", "/path/with/spaces"},
	}

	for _, tt := range tests {
		matches := sudoers.IncludedirRegex.FindStringSubmatch(tt.line)
		require.NotNil(t, matches, "line: %s", tt.line)
		assert.Equal(t, tt.expected, strings.TrimSpace(matches[1]))
	}
}

func TestIncludedirRegex_HashIncludedir(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{"#includedir /etc/sudoers.d", "/etc/sudoers.d"},
		{"#includedir /path/to/dir", "/path/to/dir"},
	}

	for _, tt := range tests {
		matches := sudoers.IncludedirRegex.FindStringSubmatch(tt.line)
		require.NotNil(t, matches, "line: %s", tt.line)
		assert.Equal(t, tt.expected, strings.TrimSpace(matches[1]))
	}
}

func TestIncludeRegex_NotMatchingLines(t *testing.T) {
	lines := []string{
		"# This is a comment about include",
		"Defaults env_reset",
		"root ALL=(ALL) ALL",
		"@includedir /etc/sudoers.d", // includedir should not match include
	}

	for _, line := range lines {
		matches := sudoers.IncludeRegex.FindStringSubmatch(line)
		assert.Nil(t, matches, "line should not match: %s", line)
	}
}

func TestIncludedirRegex_NotMatchingLines(t *testing.T) {
	lines := []string{
		"# This is a comment about includedir",
		"Defaults env_reset",
		"root ALL=(ALL) ALL",
		"@include /etc/sudoers.local", // include should not match includedir
	}

	for _, line := range lines {
		matches := sudoers.IncludedirRegex.FindStringSubmatch(line)
		assert.Nil(t, matches, "line should not match: %s", line)
	}
}

func TestParseUserSpecs(t *testing.T) {
	content := `# Sample sudoers file
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
john ALL=(ALL) NOPASSWD: ALL
`
	specs := sudoers.ParseUserSpecs("/etc/sudoers", content)

	require.Len(t, specs, 3)

	assert.Equal(t, "/etc/sudoers", specs[0].File)
	assert.Equal(t, 2, specs[0].LineNumber)
	assert.Equal(t, []string{"root"}, specs[0].Users)

	assert.Equal(t, 3, specs[1].LineNumber)
	assert.Equal(t, []string{"%sudo"}, specs[1].Users)

	assert.Equal(t, 4, specs[2].LineNumber)
	assert.Equal(t, []string{"john"}, specs[2].Users)
	assert.Equal(t, []string{"NOPASSWD"}, specs[2].Tags)
}

func TestParseDefaults(t *testing.T) {
	content := `# Sample sudoers file
Defaults env_reset
Defaults secure_path="/usr/local/sbin:/usr/local/bin"
Defaults:john !requiretty
`
	defaults := sudoers.ParseDefaults("/etc/sudoers", content)

	require.Len(t, defaults, 3)

	assert.Equal(t, "global", defaults[0].Scope)
	assert.Equal(t, "env_reset", defaults[0].Parameter)

	assert.Equal(t, "global", defaults[1].Scope)
	assert.Equal(t, "secure_path", defaults[1].Parameter)
	assert.Equal(t, "/usr/local/sbin:/usr/local/bin", defaults[1].Value)

	assert.Equal(t, "user", defaults[2].Scope)
	assert.Equal(t, "john", defaults[2].Target)
	assert.True(t, defaults[2].Negated)
}

func TestParseAliases(t *testing.T) {
	content := `# Sample sudoers file
User_Alias ADMINS = john, jane, bob
Host_Alias WEBSERVERS = web1, web2, web3
Cmnd_Alias SERVICES = /usr/bin/systemctl, /usr/bin/service
`
	aliases := sudoers.ParseAliases("/etc/sudoers", content)

	require.Len(t, aliases, 3)

	assert.Equal(t, "user", aliases[0].Type)
	assert.Equal(t, "ADMINS", aliases[0].Name)
	assert.Equal(t, []string{"john", "jane", "bob"}, aliases[0].Members)

	assert.Equal(t, "host", aliases[1].Type)
	assert.Equal(t, "WEBSERVERS", aliases[1].Name)

	assert.Equal(t, "cmnd", aliases[2].Type)
	assert.Equal(t, "SERVICES", aliases[2].Name)
}

func TestParseUserSpecs_LineContinuation(t *testing.T) {
	content := `john ALL=(ALL) NOPASSWD: \
    /usr/bin/systemctl restart nginx, \
    /usr/bin/systemctl reload nginx
`
	specs := sudoers.ParseUserSpecs("/etc/sudoers", content)

	require.Len(t, specs, 1)
	assert.Equal(t, 1, specs[0].LineNumber)
	assert.Equal(t, []string{"john"}, specs[0].Users)
	assert.Len(t, specs[0].Commands, 2)
}

// Tests with realistic sudoers content

func TestParseUserSpecs_RealisticConfig(t *testing.T) {
	content := `# /etc/sudoers
#
# This file MUST be edited with the 'visudo' command as root.

# Defaults specification
Defaults env_reset
Defaults mail_badpass
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults:root !requiretty
Defaults@webservers log_output

# Host alias specification
Host_Alias WEBSERVERS = www1, www2, www3
Host_Alias DBSERVERS = db1, db2

# User alias specification
User_Alias ADMINS = alice, bob, charlie
User_Alias OPERATORS = dave, eve

# Cmnd alias specification
Cmnd_Alias SHUTDOWN = /sbin/halt, /sbin/shutdown, /sbin/reboot
Cmnd_Alias SERVICES = /usr/bin/systemctl restart *, /usr/bin/systemctl stop *

# Runas alias specification
Runas_Alias DBA = postgres, mysql

# User privilege specification
root ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo ALL=(ALL:ALL) ALL

# ADMINS can run shutdown commands without password
ADMINS ALL=(ALL) NOPASSWD: SHUTDOWN

# Operators can manage services
OPERATORS WEBSERVERS=(root) SERVICES

# User dave can run commands as DBA users
dave ALL=(DBA) /usr/bin/psql, /usr/bin/mysql

# Include drop-in directory
@includedir /etc/sudoers.d
`
	specs := sudoers.ParseUserSpecs("/etc/sudoers", content)
	require.NotEmpty(t, specs)

	// Find root spec
	var rootSpec *sudoers.UserSpec
	for i := range specs {
		if len(specs[i].Users) > 0 && specs[i].Users[0] == "root" {
			rootSpec = &specs[i]
			break
		}
	}
	require.NotNil(t, rootSpec, "root user spec should exist")
	assert.Equal(t, "/etc/sudoers", rootSpec.File)
	assert.Equal(t, []string{"ALL"}, rootSpec.Hosts)
	assert.Equal(t, []string{"ALL"}, rootSpec.RunasUsers)
	assert.Equal(t, []string{"ALL"}, rootSpec.RunasGroups)
	assert.Equal(t, []string{"ALL"}, rootSpec.Commands)

	// Find %admin spec
	var adminSpec *sudoers.UserSpec
	for i := range specs {
		if len(specs[i].Users) > 0 && specs[i].Users[0] == "%admin" {
			adminSpec = &specs[i]
			break
		}
	}
	require.NotNil(t, adminSpec, "%admin user spec should exist")
	assert.Equal(t, []string{"ALL"}, adminSpec.Hosts)

	// Find ADMINS spec with NOPASSWD
	var adminsSpec *sudoers.UserSpec
	for i := range specs {
		if len(specs[i].Users) > 0 && specs[i].Users[0] == "ADMINS" {
			adminsSpec = &specs[i]
			break
		}
	}
	require.NotNil(t, adminsSpec, "ADMINS user spec should exist")
	assert.Equal(t, []string{"NOPASSWD"}, adminsSpec.Tags)
	assert.Equal(t, []string{"SHUTDOWN"}, adminsSpec.Commands)
}

func TestParseDefaults_RealisticConfig(t *testing.T) {
	content := `# /etc/sudoers
Defaults env_reset
Defaults mail_badpass
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults:root !requiretty
Defaults@webservers log_output
`
	defaults := sudoers.ParseDefaults("/etc/sudoers", content)
	require.NotEmpty(t, defaults)

	// Find env_reset
	var envReset *sudoers.Default
	for i := range defaults {
		if defaults[i].Parameter == "env_reset" {
			envReset = &defaults[i]
			break
		}
	}
	require.NotNil(t, envReset, "env_reset default should exist")
	assert.Equal(t, "global", envReset.Scope)
	assert.False(t, envReset.Negated)

	// Find secure_path
	var securePath *sudoers.Default
	for i := range defaults {
		if defaults[i].Parameter == "secure_path" {
			securePath = &defaults[i]
			break
		}
	}
	require.NotNil(t, securePath, "secure_path default should exist")
	assert.Contains(t, securePath.Value, "/usr/local/sbin")
	assert.Equal(t, "=", securePath.Operation)

	// Find user-scoped default
	var rootDefault *sudoers.Default
	for i := range defaults {
		if defaults[i].Scope == "user" && defaults[i].Target == "root" {
			rootDefault = &defaults[i]
			break
		}
	}
	require.NotNil(t, rootDefault, "root user-scoped default should exist")
	assert.Equal(t, "requiretty", rootDefault.Parameter)
	assert.True(t, rootDefault.Negated)

	// Find host-scoped default
	var hostDefault *sudoers.Default
	for i := range defaults {
		if defaults[i].Scope == "host" && defaults[i].Target == "webservers" {
			hostDefault = &defaults[i]
			break
		}
	}
	require.NotNil(t, hostDefault, "webservers host-scoped default should exist")
	assert.Equal(t, "log_output", hostDefault.Parameter)
}

func TestParseAliases_RealisticConfig(t *testing.T) {
	content := `# Alias definitions
Host_Alias WEBSERVERS = www1, www2, www3
Host_Alias DBSERVERS = db1, db2
User_Alias ADMINS = alice, bob, charlie
User_Alias OPERATORS = dave, eve
Cmnd_Alias SHUTDOWN = /sbin/halt, /sbin/shutdown, /sbin/reboot
Cmnd_Alias SERVICES = /usr/bin/systemctl restart *, /usr/bin/systemctl stop *
Runas_Alias DBA = postgres, mysql
`
	aliases := sudoers.ParseAliases("/etc/sudoers", content)
	require.NotEmpty(t, aliases)

	// Find WEBSERVERS
	var webserversAlias *sudoers.Alias
	for i := range aliases {
		if aliases[i].Name == "WEBSERVERS" {
			webserversAlias = &aliases[i]
			break
		}
	}
	require.NotNil(t, webserversAlias, "WEBSERVERS alias should exist")
	assert.Equal(t, "host", webserversAlias.Type)
	assert.Equal(t, []string{"www1", "www2", "www3"}, webserversAlias.Members)

	// Find ADMINS
	var adminsAlias *sudoers.Alias
	for i := range aliases {
		if aliases[i].Name == "ADMINS" {
			adminsAlias = &aliases[i]
			break
		}
	}
	require.NotNil(t, adminsAlias, "ADMINS alias should exist")
	assert.Equal(t, "user", adminsAlias.Type)
	assert.Equal(t, []string{"alice", "bob", "charlie"}, adminsAlias.Members)

	// Find SHUTDOWN
	var shutdownAlias *sudoers.Alias
	for i := range aliases {
		if aliases[i].Name == "SHUTDOWN" {
			shutdownAlias = &aliases[i]
			break
		}
	}
	require.NotNil(t, shutdownAlias, "SHUTDOWN alias should exist")
	assert.Equal(t, "cmnd", shutdownAlias.Type)
	assert.Contains(t, shutdownAlias.Members, "/sbin/halt")
	assert.Contains(t, shutdownAlias.Members, "/sbin/shutdown")
	assert.Contains(t, shutdownAlias.Members, "/sbin/reboot")

	// Find DBA
	var dbaAlias *sudoers.Alias
	for i := range aliases {
		if aliases[i].Name == "DBA" {
			dbaAlias = &aliases[i]
			break
		}
	}
	require.NotNil(t, dbaAlias, "DBA alias should exist")
	assert.Equal(t, "runas", dbaAlias.Type)
	assert.Equal(t, []string{"postgres", "mysql"}, dbaAlias.Members)
}

func TestParseUserSpecs_DropInFile(t *testing.T) {
	content := `# Developer access rules
%developers ALL=(ALL) NOPASSWD: /usr/bin/docker, /usr/bin/docker-compose
developer1 ALL=(www-data) NOPASSWD: ALL
`
	specs := sudoers.ParseUserSpecs("/etc/sudoers.d/10-developers", content)
	require.Len(t, specs, 2)

	// %developers rule
	assert.Equal(t, "/etc/sudoers.d/10-developers", specs[0].File)
	assert.Equal(t, []string{"%developers"}, specs[0].Users)
	assert.Equal(t, []string{"NOPASSWD"}, specs[0].Tags)
	assert.Contains(t, specs[0].Commands, "/usr/bin/docker")
	assert.Contains(t, specs[0].Commands, "/usr/bin/docker-compose")

	// developer1 rule
	assert.Equal(t, []string{"developer1"}, specs[1].Users)
	assert.Equal(t, []string{"www-data"}, specs[1].RunasUsers)
	assert.Equal(t, []string{"ALL"}, specs[1].Commands)
}

func TestParseUserSpecs_MonitoringDropIn(t *testing.T) {
	content := `# Monitoring access
nagios ALL=(root) NOPASSWD: /usr/lib/nagios/plugins/*, /usr/bin/systemctl status *
zabbix ALL=(root) NOPASSWD: /usr/sbin/dmidecode, /usr/bin/lsof
`
	specs := sudoers.ParseUserSpecs("/etc/sudoers.d/99-monitoring", content)
	require.Len(t, specs, 2)

	// nagios rule
	assert.Equal(t, []string{"nagios"}, specs[0].Users)
	assert.Equal(t, []string{"root"}, specs[0].RunasUsers)
	assert.Equal(t, []string{"NOPASSWD"}, specs[0].Tags)

	// zabbix rule
	assert.Equal(t, []string{"zabbix"}, specs[1].Users)
	assert.Contains(t, specs[1].Commands, "/usr/sbin/dmidecode")
	assert.Contains(t, specs[1].Commands, "/usr/bin/lsof")
}

// Regression tests for the TAB separator bug: smartSplit only treated ' ' as a
// field separator, so `root<TAB>ALL=(ALL) <TAB>ALL` produced a single token,
// tripped the `len(tokens) < 2` guard in parseLine, and was dropped. Every
// distribution ships /etc/sudoers with tab-separated fields, so userSpecs came
// back empty on stock RHEL- and Debian-family hosts while defaults still
// parsed (DefaultsRegex matches before smartSplit is reached).

func TestParseUserSpecs_TabSeparators(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		users       []string
		hosts       []string
		runasUsers  []string
		runasGroups []string
		tags        []string
		commands    []string
	}{
		{
			// verbatim from ubi10 /etc/sudoers (testdata/ubi10-etc-sudoers.txt)
			name:       "rhel root rule",
			line:       "root\tALL=(ALL) \tALL",
			users:      []string{"root"},
			hosts:      []string{"ALL"},
			runasUsers: []string{"ALL"},
			commands:   []string{"ALL"},
		},
		{
			// verbatim from ubi10 /etc/sudoers
			name:       "rhel wheel rule",
			line:       "%wheel\tALL=(ALL)\tALL",
			users:      []string{"%wheel"},
			hosts:      []string{"ALL"},
			runasUsers: []string{"ALL"},
			commands:   []string{"ALL"},
		},
		{
			// verbatim from debian:13 /etc/sudoers (testdata/debian13-etc-sudoers.txt)
			name:        "debian root rule",
			line:        "root\tALL=(ALL:ALL) ALL",
			users:       []string{"root"},
			hosts:       []string{"ALL"},
			runasUsers:  []string{"ALL"},
			runasGroups: []string{"ALL"},
			commands:    []string{"ALL"},
		},
		{
			// verbatim from debian:13 /etc/sudoers
			name:        "debian sudo group rule",
			line:        "%sudo\tALL=(ALL:ALL) ALL",
			users:       []string{"%sudo"},
			hosts:       []string{"ALL"},
			runasUsers:  []string{"ALL"},
			runasGroups: []string{"ALL"},
			commands:    []string{"ALL"},
		},
		{
			// guards the pre-existing space-separated behaviour against a fix
			// that swaps ' ' for '\t' instead of accepting both
			name:       "space separated still parses",
			line:       "root ALL=(ALL) ALL",
			users:      []string{"root"},
			hosts:      []string{"ALL"},
			runasUsers: []string{"ALL"},
			commands:   []string{"ALL"},
		},
		{
			name:       "mixed tabs and spaces with multiple users",
			line:       "alice,\tbob\tALL=(ALL)\tNOPASSWD:\t/usr/bin/id",
			users:      []string{"alice", "bob"},
			hosts:      []string{"ALL"},
			runasUsers: []string{"ALL"},
			tags:       []string{"NOPASSWD"},
			commands:   []string{"/usr/bin/id"},
		},
		{
			// a tab inside a quoted command argument is data, not a separator
			name:       "tab inside quoted argument is preserved",
			line:       "bob\tALL=(root)\t/bin/grep \"foo\tbar\" /etc/hosts",
			users:      []string{"bob"},
			hosts:      []string{"ALL"},
			runasUsers: []string{"root"},
			commands:   []string{"/bin/grep \"foo\tbar\" /etc/hosts"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specs := sudoers.ParseUserSpecs("/etc/sudoers", tt.line+"\n")
			require.Len(t, specs, 1)

			assert.Equal(t, tt.users, specs[0].Users)
			assert.Equal(t, tt.hosts, specs[0].Hosts)
			assert.Equal(t, tt.runasUsers, specs[0].RunasUsers)
			assert.Equal(t, tt.runasGroups, specs[0].RunasGroups)
			assert.Equal(t, tt.tags, specs[0].Tags)
			assert.Equal(t, tt.commands, specs[0].Commands)
		})
	}
}

func TestParseUserSpecs_TabbedLineContinuation(t *testing.T) {
	content := "john\tALL=(ALL)\tNOPASSWD: \\\n" +
		"\t/usr/bin/systemctl restart nginx, \\\n" +
		"\t/usr/bin/systemctl reload nginx\n"

	specs := sudoers.ParseUserSpecs("/etc/sudoers", content)

	require.Len(t, specs, 1)
	assert.Equal(t, 1, specs[0].LineNumber)
	assert.Equal(t, []string{"john"}, specs[0].Users)
	assert.Equal(t, []string{"NOPASSWD"}, specs[0].Tags)
	assert.Equal(t, []string{
		"/usr/bin/systemctl restart nginx",
		"/usr/bin/systemctl reload nginx",
	}, specs[0].Commands)
}

func TestSmartSplit_TabSeparated(t *testing.T) {
	assert.Equal(t, []string{"root", "ALL"}, sudoers.SmartSplit("root\tALL"))
	assert.Equal(t, []string{"user", "host", "cmd"}, sudoers.SmartSplit("user \t host\t\tcmd"))
}

func TestSmartSplit_TabInsideQuotesDoesNotSplit(t *testing.T) {
	assert.Equal(t, []string{"user", "host", "\"a\tb\""}, sudoers.SmartSplit("user\thost\t\"a\tb\""))
}

func TestParseDefaultsLine_TabAfterScopeTarget(t *testing.T) {
	// A scoped Defaults target may be separated from its parameter by a tab.
	scope, target, parameter, value, operation, negated := sudoers.ParseDefaultsLine("Defaults:john\t!requiretty")

	assert.Equal(t, "user", scope)
	assert.Equal(t, "john", target)
	assert.Equal(t, "requiretty", parameter)
	assert.Equal(t, "", value)
	assert.Equal(t, "", operation)
	assert.True(t, negated)
}

// The two files below were captured from the stock images, not hand-written,
// so their separators are the real bytes those distributions ship.

func TestParseSudoers_UBI10Fixture(t *testing.T) {
	content := readSudoersFixture(t, "testdata/ubi10-etc-sudoers.txt")

	specs := sudoers.ParseUserSpecs("/etc/sudoers", content)
	require.Len(t, specs, 2)
	assert.Equal(t, []string{"root"}, specs[0].Users)
	assert.Equal(t, []string{"ALL"}, specs[0].Hosts)
	assert.Equal(t, []string{"ALL"}, specs[0].RunasUsers)
	assert.Equal(t, []string{"ALL"}, specs[0].Commands)
	assert.Equal(t, []string{"%wheel"}, specs[1].Users)
	assert.Equal(t, []string{"ALL"}, specs[1].Commands)

	// defaults parsed before the fix and must keep parsing after it
	assert.Len(t, sudoers.ParseDefaults("/etc/sudoers", content), 11)
}

func TestParseSudoers_Debian13Fixture(t *testing.T) {
	content := readSudoersFixture(t, "testdata/debian13-etc-sudoers.txt")

	specs := sudoers.ParseUserSpecs("/etc/sudoers", content)
	require.Len(t, specs, 2)
	assert.Equal(t, []string{"root"}, specs[0].Users)
	assert.Equal(t, []string{"ALL"}, specs[0].RunasUsers)
	assert.Equal(t, []string{"ALL"}, specs[0].RunasGroups)
	assert.Equal(t, []string{"ALL"}, specs[0].Commands)
	assert.Equal(t, []string{"%sudo"}, specs[1].Users)
	assert.Equal(t, []string{"ALL"}, specs[1].Commands)

	assert.Len(t, sudoers.ParseDefaults("/etc/sudoers", content), 4)
}

func readSudoersFixture(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(raw), "\t", "fixture lost its tabs")
	return string(raw)
}
