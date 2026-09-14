// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sshd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sshd_config permits a quoted Include path, and some distributions quote
// unconditionally. Flatcar's entire config is one line:
//
//	Include "/etc/ssh/sshd_config.d/*.conf"
//
// Splitting on spaces left the quotes inside the glob, so it matched nothing
// and the whole included config was dropped silently.
func TestSplitIncludeArgs(t *testing.T) {
	tests := []struct {
		name string
		args string
		want []string
	}{
		{
			name: "unquoted, the common form",
			args: "/etc/ssh/sshd_config.d/*.conf",
			want: []string{"/etc/ssh/sshd_config.d/*.conf"},
		},
		{
			// the reported case
			name: "double quoted",
			args: `"/etc/ssh/sshd_config.d/*.conf"`,
			want: []string{"/etc/ssh/sshd_config.d/*.conf"},
		},
		{
			name: "single quoted",
			args: `'/etc/ssh/sshd_config.d/*.conf'`,
			want: []string{"/etc/ssh/sshd_config.d/*.conf"},
		},
		{
			name: "multiple unquoted paths",
			args: "/etc/ssh/a.conf /etc/ssh/b.conf",
			want: []string{"/etc/ssh/a.conf", "/etc/ssh/b.conf"},
		},
		{
			name: "mixed quoted and unquoted",
			args: `"/etc/ssh/a.conf" /etc/ssh/b.conf`,
			want: []string{"/etc/ssh/a.conf", "/etc/ssh/b.conf"},
		},
		{
			// the reason quoting exists in the first place
			name: "quoted path containing a space stays one argument",
			args: `"/etc/ssh/my configs/*.conf"`,
			want: []string{"/etc/ssh/my configs/*.conf"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, splitIncludeArgs(tc.args))
		})
	}
}

// Malformed quoting must not drop the directive entirely; fall back to the
// plain split so behaviour is no worse than before.
func TestSplitIncludeArgsUnbalancedQuote(t *testing.T) {
	got := splitIncludeArgs(`"/etc/ssh/unterminated.conf`)
	require.NotEmpty(t, got)
	assert.Equal(t, []string{`"/etc/ssh/unterminated.conf`}, got)
}
