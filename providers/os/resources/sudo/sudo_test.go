// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sudo_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/sudo"
)

// fullSudoVOutput is a faithful capture of `sudo -V` run as root on a
// modern Debian 12 host. It exercises the version line, configure
// options (including --enable-python), and every plugin family.
const fullSudoVOutput = `Sudo version 1.9.13p3
Sudoers policy plugin version 1.9.13p3
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.13p3
Sudoers audit plugin version 1.9.13p3
Sudoers approval plugin version 1.9.13p3
Configure options: --prefix=/usr --with-all-insults --with-pam --enable-python --with-secure-path
Sudo configuration: ...
`

func TestParseVersionOutput_VersionLine(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"semver with patch letter", "Sudo version 1.9.5p3", "1.9.5p3"},
		{"semver double-digit patch", "Sudo version 1.9.5p11", "1.9.5p11"},
		{"semver no patch suffix", "Sudo version 1.8.31", "1.8.31"},
		{"leading whitespace", "   Sudo version 1.9.0", "1.9.0"},
		{"version embedded in output", fullSudoVOutput, "1.9.13p3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sudo.ParseVersionOutput(c.in)
			assert.Equal(t, c.want, got.Version)
		})
	}
}

func TestParseVersionOutput_NoVersionLine(t *testing.T) {
	got := sudo.ParseVersionOutput("nothing to see here\n")
	assert.Empty(t, got.Version)
	assert.Empty(t, got.Plugins)
	assert.False(t, got.PythonSupport)
}

func TestParseVersionOutput_EmptyInput(t *testing.T) {
	got := sudo.ParseVersionOutput("")
	assert.Empty(t, got.Version)
	assert.Empty(t, got.Plugins)
	assert.False(t, got.PythonSupport)
}

func TestParseVersionOutput_PluginsAllTypes(t *testing.T) {
	got := sudo.ParseVersionOutput(fullSudoVOutput)
	require.Len(t, got.Plugins, 4)

	byName := make(map[string]sudo.Plugin)
	for _, p := range got.Plugins {
		byName[p.Name] = p
	}

	assert.Equal(t, "policy", byName["sudoers_policy"].Type)
	assert.Equal(t, "1.9.13p3", byName["sudoers_policy"].Version)

	assert.Equal(t, "io", byName["sudoers_io"].Type)
	assert.Equal(t, "1.9.13p3", byName["sudoers_io"].Version)

	assert.Equal(t, "audit", byName["sudoers_audit"].Type)
	assert.Equal(t, "approval", byName["sudoers_approval"].Type)
}

func TestParseVersionOutput_PythonPlugins(t *testing.T) {
	// Python plugin lines: signal that the build supports Python plugins
	// AND emit Plugin entries with python_* names.
	out := `Sudo version 1.9.13p3
Sudoers policy plugin version 1.9.13p3
Python policy plugin version 1.9.13p3
Python I/O plugin version 1.9.13p3
`
	got := sudo.ParseVersionOutput(out)
	assert.True(t, got.PythonSupport, "python plugin lines should imply python support")

	require.Len(t, got.Plugins, 3)
	names := map[string]bool{}
	for _, p := range got.Plugins {
		names[p.Name] = true
	}
	assert.Contains(t, names, "python_policy")
	assert.Contains(t, names, "python_io")
}

func TestParseVersionOutput_PythonSupport_ViaConfigureOptions(t *testing.T) {
	out := `Sudo version 1.9.13p3
Sudoers policy plugin version 1.9.13p3
Configure options: --prefix=/usr --enable-python
`
	got := sudo.ParseVersionOutput(out)
	assert.True(t, got.PythonSupport)
}

func TestParseVersionOutput_PythonSupport_AbsentByDefault(t *testing.T) {
	out := `Sudo version 1.9.13p3
Sudoers policy plugin version 1.9.13p3
Configure options: --prefix=/usr --with-pam
`
	got := sudo.ParseVersionOutput(out)
	assert.False(t, got.PythonSupport, "no python signal should mean no python support")
}

func TestParseVersionOutput_IOPluginNormalization(t *testing.T) {
	// `sudo -V` prints "I/O" but the MQL type field should be "io".
	out := `Sudo version 1.9.5
Sudoers I/O plugin version 1.9.5
`
	got := sudo.ParseVersionOutput(out)
	require.Len(t, got.Plugins, 1)
	assert.Equal(t, "io", got.Plugins[0].Type)
	assert.Equal(t, "sudoers_io", got.Plugins[0].Name)
}

func TestParseVersionOutput_NonRootShortOutput(t *testing.T) {
	// Unprivileged `sudo -V` typically omits Configure options. The
	// parser must still extract version + plugins from the lines that
	// are emitted.
	out := `Sudo version 1.9.5p2
Sudoers policy plugin version 1.9.5p2
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.5p2
Sudoers audit plugin version 1.9.5p2
`
	got := sudo.ParseVersionOutput(out)
	assert.Equal(t, "1.9.5p2", got.Version)
	assert.Len(t, got.Plugins, 3) // policy + io + audit
	assert.False(t, got.PythonSupport, "non-root output without python plugin = no support detected")
}

func TestParseVersionOutput_LegacySudo18(t *testing.T) {
	// sudo 1.8.x predates the audit/approval plugin families.
	out := `Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
`
	got := sudo.ParseVersionOutput(out)
	assert.Equal(t, "1.8.31", got.Version)
	assert.Len(t, got.Plugins, 2)
	// No audit/approval plugins in 1.8.x.
	assert.Empty(t, sudo.PluginsByType(got.Plugins, "audit"))
	assert.Empty(t, sudo.PluginsByType(got.Plugins, "approval"))
}

func TestPluginsByType(t *testing.T) {
	plugins := []sudo.Plugin{
		{Name: "sudoers_policy", Type: "policy"},
		{Name: "sudoers_io", Type: "io"},
		{Name: "sudoers_audit", Type: "audit"},
		{Name: "python_io", Type: "io"},
	}

	assert.Len(t, sudo.PluginsByType(plugins, "io"), 2)
	assert.Len(t, sudo.PluginsByType(plugins, "policy"), 1)
	assert.Len(t, sudo.PluginsByType(plugins, "approval"), 0)
	assert.Nil(t, sudo.PluginsByType(plugins, "approval"),
		"missing type returns nil so MQL can surface null vs empty array")
}

func TestFirstPluginByType(t *testing.T) {
	plugins := []sudo.Plugin{
		{Name: "sudoers_io", Type: "io", Version: "1.9.5"},
		{Name: "python_io", Type: "io", Version: "1.9.5"},
	}

	first := sudo.FirstPluginByType(plugins, "io")
	require.NotNil(t, first)
	assert.Equal(t, "sudoers_io", first.Name, "should return the first matching plugin")

	assert.Nil(t, sudo.FirstPluginByType(plugins, "audit"))
}

func TestParseVisudoErrors_NoErrors(t *testing.T) {
	out := `parsed OK
/etc/sudoers: parsed OK
/etc/sudoers.d/extra: parsed OK
`
	errs := sudo.ParseVisudoErrors(out)
	assert.Empty(t, errs)
}

func TestParseVisudoErrors_SingleError(t *testing.T) {
	out := `>>> /etc/sudoers: syntax error near line 42 <<<
parse error in /etc/sudoers near line 42
`
	errs := sudo.ParseVisudoErrors(out)
	require.Len(t, errs, 1)
	assert.Equal(t, "/etc/sudoers", errs[0].File)
	assert.Equal(t, 42, errs[0].Line)
	assert.Equal(t, "syntax error", errs[0].Message)
}

func TestParseVisudoErrors_MultipleErrors(t *testing.T) {
	out := `>>> /etc/sudoers: syntax error near line 12 <<<
>>> /etc/sudoers.d/extra: unknown defaults entry near line 3 <<<
`
	errs := sudo.ParseVisudoErrors(out)
	require.Len(t, errs, 2)
	assert.Equal(t, "/etc/sudoers", errs[0].File)
	assert.Equal(t, 12, errs[0].Line)
	assert.Equal(t, "/etc/sudoers.d/extra", errs[1].File)
	assert.Equal(t, 3, errs[1].Line)
	assert.Equal(t, "unknown defaults entry", errs[1].Message)
}

func TestParseVisudoErrors_EmptyInput(t *testing.T) {
	assert.Empty(t, sudo.ParseVisudoErrors(""))
}

func TestParseVisudoErrors_ColonFormat(t *testing.T) {
	// `visudo -c` emits this shape when a Defaults entry is wrong:
	out := `/etc/sudoers: Invalid Defaults entry: badparam
`
	errs := sudo.ParseVisudoErrors(out)
	require.Len(t, errs, 1)
	assert.Equal(t, "/etc/sudoers", errs[0].File)
	assert.Equal(t, 0, errs[0].Line, "colon-format errors have no line number")
	assert.Equal(t, "Invalid Defaults entry: badparam", errs[0].Message)
}

func TestParseVisudoErrors_MixedFormats(t *testing.T) {
	// Both formats can appear in the same run (e.g., a syntax error in
	// one included file and an unknown defaults entry in another).
	out := `>>> /etc/sudoers: syntax error near line 7 <<<
/etc/sudoers.d/extra: Invalid Defaults entry: pwfeedbck
`
	errs := sudo.ParseVisudoErrors(out)
	require.Len(t, errs, 2)

	assert.Equal(t, "/etc/sudoers", errs[0].File)
	assert.Equal(t, 7, errs[0].Line)

	assert.Equal(t, "/etc/sudoers.d/extra", errs[1].File)
	assert.Equal(t, 0, errs[1].Line)
	assert.Equal(t, "Invalid Defaults entry: pwfeedbck", errs[1].Message)
}

func TestParseVisudoErrors_ParsedOKIsNotAnError(t *testing.T) {
	// On success, visudo prints `<file>: parsed OK` lines. These must
	// not be flagged as errors — they share the colon-format shape.
	out := `/etc/sudoers: parsed OK
/etc/sudoers.d/extra: parsed OK
`
	errs := sudo.ParseVisudoErrors(out)
	assert.Empty(t, errs)
}

func TestParseVisudoErrors_PartialSuccess(t *testing.T) {
	// Real visudo output often mixes success markers for some files
	// with errors in others. Only the errors should be captured.
	out := `/etc/sudoers: parsed OK
/etc/sudoers.d/broken: Invalid Defaults entry: pwfeedbck
/etc/sudoers.d/another: parsed OK
`
	errs := sudo.ParseVisudoErrors(out)
	require.Len(t, errs, 1)
	assert.Equal(t, "/etc/sudoers.d/broken", errs[0].File)
}

func TestParseVisudoErrors_DropsUnrecognizedNoise(t *testing.T) {
	// Lines that match neither error format nor the success marker
	// are dropped at the parser layer. The resolver synthesizes a
	// fallback error from the raw output when visudo exits non-zero
	// and the parser returned nothing — that behavior is covered by
	// the resolver-level test.
	out := `some random banner text
not a path: not a real error
`
	errs := sudo.ParseVisudoErrors(out)
	assert.Empty(t, errs)
}

func TestParseVersionOutput_GroupFamilyNotRecognized(t *testing.T) {
	// Regression: the regex must not invent a `Group` plugin family.
	// Sudo's group_plugin feature does not emit a `Group X plugin
	// version Y` line, so any such line would be malformed and must
	// be ignored.
	out := `Sudo version 1.9.13p3
Group policy plugin version 1.9.13p3
`
	got := sudo.ParseVersionOutput(out)
	assert.Equal(t, "1.9.13p3", got.Version)
	assert.Empty(t, got.Plugins, "no `Group` plugin family should be recognized")
}

func TestParseVersionOutput_PluginVersionsPreserved(t *testing.T) {
	// Some Linux distros patch the policy plugin to a different version
	// than the sudo binary itself (rare, but legal). Make sure we don't
	// flatten plugin versions onto the binary version.
	out := `Sudo version 1.9.5p3
Sudoers policy plugin version 1.9.5p3-1ubuntu1
`
	got := sudo.ParseVersionOutput(out)
	assert.Equal(t, "1.9.5p3", got.Version)
	require.Len(t, got.Plugins, 1)
	assert.Equal(t, "1.9.5p3-1ubuntu1", got.Plugins[0].Version)
}

func TestParseVersionOutput_BlankAndCommentLinesIgnored(t *testing.T) {
	out := `

Sudo version 1.9.5

# this line is not real but proves the parser tolerates noise

Sudoers policy plugin version 1.9.5

`
	got := sudo.ParseVersionOutput(out)
	assert.Equal(t, "1.9.5", got.Version)
	assert.Len(t, got.Plugins, 1)
}

// sudoRsVOutput is `sudo -V` on Ubuntu 26.04, where /usr/bin/sudo resolves
// through update-alternatives to sudo-rs (/usr/lib/cargo/bin/sudo).
const sudoRsVOutput = "sudo-rs 0.2.13-0ubuntu1.2\n"

// ubuntu2404SudoVOutput is the head of `sudo -V` run as root on Ubuntu 24.04
// (sudo 1.9.15p5), configure options elided.
const ubuntu2404SudoVOutput = `Sudo version 1.9.15p5
Configure options: --build=x86_64-linux-gnu --prefix=/usr --with-pam --with-logging=syslog
Sudoers policy plugin version 1.9.15p5
Sudoers file grammar version 50

Sudoers path: /etc/sudoers
Authentication methods: 'pam'
`

func TestParseVersionOutput_Implementation(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantImpl string
		wantVer  string
	}{
		{"sudo-rs on Ubuntu 26.04 drops package revision", sudoRsVOutput, sudo.ImplementationSudoRs, "0.2.13"},
		{"sudo-rs upstream build", "sudo-rs 0.2.8\n", sudo.ImplementationSudoRs, "0.2.8"},
		{"sudo on Ubuntu 24.04", ubuntu2404SudoVOutput, sudo.ImplementationSudo, "1.9.15p5"},
		{"sudo on Debian 12", fullSudoVOutput, sudo.ImplementationSudo, "1.9.13p3"},
		{"unrecognized banner", "nothing to see here\n", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sudo.ParseVersionOutput(c.in)
			assert.Equal(t, c.wantImpl, got.Implementation)
			assert.Equal(t, c.wantVer, got.Version)
		})
	}
}

func TestParseVersionOutput_SudoRsHasNoPlugins(t *testing.T) {
	got := sudo.ParseVersionOutput(sudoRsVOutput)
	assert.Empty(t, got.Plugins)
	assert.False(t, got.PythonSupport)
}
