// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sudoers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveIncludePath(t *testing.T) {
	host := func() string { return "ip-10-0-1-5.us-west-2.compute.internal" }
	noHost := func() string { return "" }

	tests := []struct {
		name      string
		including string
		arg       string
		host      func() string
		want      string
	}{
		{
			// RHEL 9 sweep fixture: /etc/sudoers.d/mqltest holds this line and
			// sudo reads /etc/sudoers.mqlrel (verified with `sudo -l -U`).
			name:      "relative path resolves against the including file's directory",
			including: "/etc/sudoers.d/mqltest",
			arg:       "../sudoers.mqlrel",
			host:      host,
			want:      "/etc/sudoers.mqlrel",
		},
		{
			name:      "bare file name next to /etc/sudoers",
			including: "/etc/sudoers",
			arg:       "sudoers.local",
			host:      host,
			want:      "/etc/sudoers.local",
		},
		{
			name:      "relative includedir",
			including: "/usr/local/etc/sudoers",
			arg:       "sudoers.d",
			host:      host,
			want:      "/usr/local/etc/sudoers.d",
		},
		{
			name:      "absolute path is kept",
			including: "/etc/sudoers.d/mqltest",
			arg:       "/etc/sudoers.d",
			host:      host,
			want:      "/etc/sudoers.d",
		},
		{
			name:      "%h expands to the short host name",
			including: "/etc/sudoers",
			arg:       "/etc/sudoers.%h",
			host:      host,
			want:      "/etc/sudoers.ip-10-0-1-5",
		},
		{
			name:      "%h with a relative path",
			including: "/etc/sudoers",
			arg:       "sudoers.d/%h",
			host:      host,
			want:      "/etc/sudoers.d/ip-10-0-1-5",
		},
		{
			name:      "%h kept when the host name is unknown",
			including: "/etc/sudoers",
			arg:       "/etc/sudoers.%h",
			host:      noHost,
			want:      "/etc/sudoers.%h",
		},
		{
			name:      "double-quoted path with a space",
			including: "/etc/sudoers",
			arg:       `"/etc/sudo rules/extra"`,
			host:      host,
			want:      "/etc/sudo rules/extra",
		},
		{
			name:      "backslash-escaped space",
			including: "/etc/sudoers",
			arg:       `sudo\ rules/extra`,
			host:      host,
			want:      "/etc/sudo rules/extra",
		},
		{
			name:      "surrounding whitespace",
			including: "/etc/sudoers",
			arg:       "  /etc/sudoers.d  ",
			host:      host,
			want:      "/etc/sudoers.d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ResolveIncludePath(tt.including, tt.arg, tt.host))
		})
	}
}

func TestResolveIncludePath_HostLookupOnlyForPercentH(t *testing.T) {
	called := false
	got := ResolveIncludePath("/etc/sudoers", "/etc/sudoers.d", func() string {
		called = true
		return "box"
	})
	assert.Equal(t, "/etc/sudoers.d", got)
	assert.False(t, called, "the host name is resolved only when the path contains %h")
}

func TestShortHostname(t *testing.T) {
	assert.Equal(t, "web01", ShortHostname("web01.example.com"))
	assert.Equal(t, "web01", ShortHostname("web01"))
	assert.Equal(t, "", ShortHostname(""))
}

func TestIsIncludedirEntry(t *testing.T) {
	tests := []struct {
		name     string
		dir      string
		path     string
		basename string
		want     bool
	}{
		{"file directly in the directory", "/etc/sudoers.d", "/etc/sudoers.d/mqltest", "mqltest", true},
		{"trailing slash on the directory", "/etc/sudoers.d/", "/etc/sudoers.d/mqltest", "mqltest", true},
		// RHEL 9 sweep fixture: sudo ignores /etc/sudoers.d/mqlsub/inner.
		{"file in a subdirectory", "/etc/sudoers.d", "/etc/sudoers.d/mqlsub/inner", "inner", false},
		{"name with a dot", "/etc/sudoers.d", "/etc/sudoers.d/mql.ignored", "mql.ignored", false},
		{"rpmnew leftover", "/etc/sudoers.d", "/etc/sudoers.d/wheel.rpmnew", "wheel.rpmnew", false},
		{"editor backup", "/etc/sudoers.d", "/etc/sudoers.d/mqlbackup~", "mqlbackup~", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsIncludedirEntry(tt.dir, tt.path, tt.basename))
		})
	}
}
