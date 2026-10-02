// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestPostfixConfigDir(t *testing.T) {
	tests := []struct {
		platform string
		expected string
	}{
		{"debian", "/etc/postfix"},
		{"ubuntu", "/etc/postfix"},
		{"redhat", "/etc/postfix"},
		{"macos", "/etc/postfix"},
		{"freebsd", "/usr/local/etc/postfix"},
		{"dragonflybsd", "/usr/local/etc/postfix"},
		{"netbsd", "/usr/pkg/etc/postfix"},
	}
	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			assert.Equal(t, tt.expected, postfixConfigDir(connWithPlatform(tt.platform)))
		})
	}

	t.Run("nil platform falls back to /etc/postfix", func(t *testing.T) {
		assert.Equal(t, "/etc/postfix", postfixConfigDir(&mockConn{asset: &inventory.Asset{}}))
	})
}

func TestParsePostconf(t *testing.T) {
	out := "inet_interfaces = loopback-only\n" +
		"myhostname = mail.example.com\n" +
		"smtpd_banner = $myhostname ESMTP\n" +
		"# not a real line\n"
	got := parsePostconf(out)
	assert.Equal(t, "loopback-only", got["inet_interfaces"])
	assert.Equal(t, "mail.example.com", got["myhostname"])
	// postconf already expands $vars, so we keep its output verbatim
	assert.Equal(t, "$myhostname ESMTP", got["smtpd_banner"])
}

func TestParsePostfixMainCf(t *testing.T) {
	t.Run("key=value, comments and blank lines", func(t *testing.T) {
		content := "# main.cf\n\ninet_interfaces = localhost\nmydestination = example.com\n"
		got := parsePostfixMainCf(content)
		assert.Equal(t, map[string]any{
			"inet_interfaces": "localhost",
			"mydestination":   "example.com",
		}, got)
	})

	t.Run("continuation lines fold into the previous value", func(t *testing.T) {
		content := "mynetworks = 127.0.0.0/8\n  [::1]/128\n"
		got := parsePostfixMainCf(content)
		assert.Equal(t, "127.0.0.0/8 [::1]/128", got["mynetworks"])
	})

	t.Run("$name interpolation against file values", func(t *testing.T) {
		content := "myhostname = mail.example.com\nmyorigin = $myhostname\nbanner = ${myhostname} ESMTP\n"
		got := parsePostfixMainCf(content)
		assert.Equal(t, "mail.example.com", got["myorigin"])
		assert.Equal(t, "mail.example.com ESMTP", got["banner"])
	})

	t.Run("unknown variables are left untouched", func(t *testing.T) {
		content := "relayhost = $unset_var\n"
		got := parsePostfixMainCf(content)
		assert.Equal(t, "$unset_var", got["relayhost"])
	})

	t.Run("comment and blank lines do not break continuation", func(t *testing.T) {
		// Postfix 3.8 (SLES 15 SP7): `postconf -c dir -n` on this file reports
		// smtpd_client_restrictions = permit_mynetworks, reject and a=1  b.
		content := "smtpd_client_restrictions =\n" +
			"    permit_mynetworks,\n" +
			"#   reject_unknown_client_hostname,\n" +
			"    reject\n" +
			"a = 1\n" +
			"\n" +
			"  b\n" +
			"z = 3\n" +
			"   # indented comment\n" +
			"  w\n"
		got := parsePostfixMainCf(content)
		assert.Equal(t, map[string]any{
			"smtpd_client_restrictions": "permit_mynetworks, reject",
			"a":                         "1 b",
			"z":                         "3 w",
		}, got)
	})

	t.Run("indented text before the first parameter is discarded", func(t *testing.T) {
		got := parsePostfixMainCf("  stray = 1\n  more\nmyhostname = mail.example.com\n")
		assert.Equal(t, map[string]any{"myhostname": "mail.example.com"}, got)
	})
}

func TestSplitPostfixList(t *testing.T) {
	assert.Equal(t, []any{"127.0.0.1", "::1"}, splitPostfixList("127.0.0.1, ::1"))
	assert.Equal(t, []any{"127.0.0.1", "::1"}, splitPostfixList("127.0.0.1  ::1"))
	assert.Equal(t, []any{"localhost"}, splitPostfixList("localhost"))
	assert.Equal(t, []any{}, splitPostfixList(""))
}

func TestParseMasterCf(t *testing.T) {
	content := "# service type  private unpriv  chroot  wakeup  maxproc command\n" +
		"smtp      inet  n       -       y       -       -       smtpd\n" +
		"pickup    unix  n       -       y       60      1       pickup\n" +
		"submission inet n       -       y       -       -       smtpd\n" +
		"  -o syslog_name=postfix/submission\n" // continuation folds into command

	got := parseMasterCf(content)
	assert.Len(t, got, 3)

	assert.Equal(t, masterCfEntry{
		Service: "smtp", Type: "inet", Private: "n", Unprivileged: "-",
		Chroot: "y", Wakeup: "-", MaxProcesses: "-", Command: "smtpd",
	}, got[0])

	assert.Equal(t, "pickup", got[1].Command)
	assert.Equal(t, "60", got[1].Wakeup)

	// the continuation line is appended to the submission command
	assert.Equal(t, "smtpd -o syslog_name=postfix/submission", got[2].Command)
}

func TestParseMasterCfOptionsAfterComment(t *testing.T) {
	// Postfix 3.8 `postconf -M smtps/inet` on this master.cf ends with
	// -o smtpd_tls_security_level=none: the commented-out option does not end
	// the smtps entry.
	content := "smtps     inet  n       -       n       -       -       smtpd\n" +
		"  -o smtpd_tls_wrappermode=yes\n" +
		"#  -o smtpd_tls_security_level=encrypt\n" +
		"  -o smtpd_tls_security_level=none\n" +
		"\n" +
		"  -o smtpd_sasl_auth_enable=no\n" +
		"pickup    unix  n       -       y       60      1       pickup\n"

	got := parseMasterCf(content)
	require.Len(t, got, 2)
	assert.Equal(t, "smtpd -o smtpd_tls_wrappermode=yes -o smtpd_tls_security_level=none -o smtpd_sasl_auth_enable=no", got[0].Command)
	assert.Equal(t, "pickup", got[1].Command)
}
