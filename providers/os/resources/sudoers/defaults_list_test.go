// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sudoers_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/sudoers"
)

// A Defaults line sets a comma-separated list of parameters (sudoers(5),
// Parameter_List): each item is its own setting.
func TestParseDefaultsEntries(t *testing.T) {
	type setting = sudoers.DefaultSetting
	cases := []struct {
		line   string
		scope  string
		target string
		want   []setting
	}{
		{
			line:  "Defaults env_reset, timestamp_timeout=15",
			scope: "global",
			want: []setting{
				{Parameter: "env_reset"},
				{Parameter: "timestamp_timeout", Value: "15", Operation: "="},
			},
		},
		{
			line:  "Defaults\tuse_pty,logfile=\"/var/log/sudo.log\" ,  !visiblepw",
			scope: "global",
			want: []setting{
				{Parameter: "use_pty"},
				{Parameter: "logfile", Value: "/var/log/sudo.log", Operation: "="},
				{Parameter: "visiblepw", Negated: true},
			},
		},
		{
			// a comma inside quotes or escaped belongs to the value
			line:  `Defaults env_keep += "LANG, LC_ALL", mailsub="a\,b", passprompt=x=y`,
			scope: "global",
			want: []setting{
				{Parameter: "env_keep", Value: "LANG, LC_ALL", Operation: "+="},
				{Parameter: "mailsub", Value: "a,b", Operation: "="},
				{Parameter: "passprompt", Value: "x=y", Operation: "="},
			},
		},
		{
			line:  "Defaults env_delete-=TZ, !!lecture",
			scope: "global",
			want: []setting{
				{Parameter: "env_delete", Value: "TZ", Operation: "-="},
				// each '!' toggles the negation
				{Parameter: "lecture"},
			},
		},
		{
			line:   "Defaults:alice,%wheel !authenticate, timestamp_timeout=0",
			scope:  "user",
			target: "alice,%wheel",
			want: []setting{
				{Parameter: "authenticate", Negated: true},
				{Parameter: "timestamp_timeout", Value: "0", Operation: "="},
			},
		},
		{
			// whitespace next to a target list's comma continues the list
			line:   "Defaults:alice, bob\t!lecture",
			scope:  "user",
			target: "alice,bob",
			want:   []setting{{Parameter: "lecture", Negated: true}},
		},
		{
			line:   "Defaults@db1,db2 log_output, iolog_dir=/var/log/sudo-io",
			scope:  "host",
			target: "db1,db2",
			want: []setting{
				{Parameter: "log_output"},
				{Parameter: "iolog_dir", Value: "/var/log/sudo-io", Operation: "="},
			},
		},
		{
			line:   "Defaults>root,operator !set_logname, env_reset",
			scope:  "runas",
			target: "root,operator",
			want: []setting{
				{Parameter: "set_logname", Negated: true},
				{Parameter: "env_reset"},
			},
		},
		{
			line:   "Defaults!/usr/bin/more, /usr/bin/pg noexec, !use_pty",
			scope:  "command",
			target: "/usr/bin/more,/usr/bin/pg",
			want: []setting{
				{Parameter: "noexec"},
				{Parameter: "use_pty", Negated: true},
			},
		},
		{
			// an empty item between commas is not a setting
			line:  "Defaults env_reset,,",
			scope: "global",
			want:  []setting{{Parameter: "env_reset"}},
		},
	}

	for _, c := range cases {
		t.Run(c.line, func(t *testing.T) {
			scope, target, settings := sudoers.ParseDefaultsEntries(c.line)
			assert.Equal(t, c.scope, scope)
			assert.Equal(t, c.target, target)
			assert.Equal(t, c.want, settings)
		})
	}
}

// Every setting of a line becomes its own Default, sharing the line's file,
// number and raw text.
func TestParseDefaults_List(t *testing.T) {
	content := `Defaults env_reset, timestamp_timeout=15
Defaults:ops !lecture, \
	passwd_tries=2
Defaults use_pty
`
	defaults := sudoers.ParseDefaults("/usr/local/etc/sudoers", content)
	require.Len(t, defaults, 5)

	assert.Equal(t, "env_reset", defaults[0].Parameter)
	assert.Equal(t, 0, defaults[0].Index)
	assert.Equal(t, "timestamp_timeout", defaults[1].Parameter)
	assert.Equal(t, "15", defaults[1].Value)
	assert.Equal(t, 1, defaults[1].Index)
	assert.Equal(t, 1, defaults[1].LineNumber)
	assert.Equal(t, "Defaults env_reset, timestamp_timeout=15", defaults[1].Raw)

	assert.Equal(t, "lecture", defaults[2].Parameter)
	assert.True(t, defaults[2].Negated)
	assert.Equal(t, "passwd_tries", defaults[3].Parameter)
	assert.Equal(t, "2", defaults[3].Value)
	assert.Equal(t, "user", defaults[3].Scope)
	assert.Equal(t, "ops", defaults[3].Target)
	assert.Equal(t, 2, defaults[3].LineNumber)

	assert.Equal(t, "use_pty", defaults[4].Parameter)
	assert.Equal(t, 0, defaults[4].Index)
	assert.Equal(t, 4, defaults[4].LineNumber)
}
