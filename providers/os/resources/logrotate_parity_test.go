// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// `logrotate -d` on the RHEL and Debian test hosts with
// /etc/logrotate.d/g04tab and copies of it under every taboo-candidate
// extension. Read: g04tab.old and g04tab.bak on 3.8.6 (RHEL 7), 3.11
// (Ubuntu 18.04, Debian 9) and 3.14 (RHEL 8, Ubuntu 20.04, Debian 10);
// g04tab.old on 3.18 (RHEL 9, Debian 11) and 3.21 (Ubuntu 24.04, Debian 12);
// neither on 3.22 (Fedora 44, Ubuntu 26.04, Debian 13). Ignored on every
// version: .rpmnew, .rpmsave, .disabled, .swp, .dpkg-old.
func TestLogrotateDropInFilterByVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		read    []string
		ignored []string
	}{
		{"3.8.6", []string{"g04tab", "g04tab.old", "g04tab.bak", "g04tab.new", "g04tab.orig"}, []string{"g04tab.rpmnew", "g04tab.rpmsave", "g04tab.disabled", "g04tab.swp", "g04tab.dpkg-old"}},
		{"3.11.0", []string{"g04tab.old", "g04tab.bak"}, []string{"g04tab.disabled", "g04tab.swp", "g04tab.rpmnew"}},
		{"3.14.0", []string{"g04tab.old", "g04tab.bak"}, []string{"g04tab.disabled", "g04tab.swp"}},
		{"3.18.0", []string{"g04tab.old", "g04tab.new", "g04tab.orig"}, []string{"g04tab.bak", "g04tab.disabled", "g04tab.swp"}},
		{"3.21.0", []string{"g04tab.old"}, []string{"g04tab.bak", "g04tab.disabled"}},
		{"3.22.0", []string{"g04tab"}, []string{"g04tab.old", "g04tab.bak", "g04tab.new", "g04tab.orig", "g04tab.disabled", "g04tab.swp"}},
	} {
		skip := logrotateDropInSkip(tc.version, false)
		for _, name := range tc.read {
			assert.False(t, skip(name), "%s reads %s", tc.version, name)
		}
		for _, name := range tc.ignored {
			assert.True(t, skip(name), "%s ignores %s", tc.version, name)
		}
	}

	// without a version, outside SUSE, the suffix list mql always used
	skip := logrotateDropInSkip("", false)
	assert.True(t, skip("g04tab.bak"))
	assert.True(t, skip("g04tab.old"))
	// on SUSE an unknown version reads as SLE 15's 3.18
	skip = logrotateDropInSkip("", true)
	assert.False(t, skip("g04tab.old"))
	assert.True(t, skip("g04tab.disabled"))
}

// logrotate 3.18 and later, and RHEL 8's 3.14.0-6, skip a whole file with a
// syntax error ("found error in file g04crlf, skipping"); with CRLF line
// endings every "{" and "}" line is one. 3.8.6, 3.11 and Debian's 3.14 log the
// error and keep the file's rules.
func TestLogrotateStrictParsing(t *testing.T) {
	assert.False(t, logrotateStrictParsing("3.8.6", ""))
	assert.False(t, logrotateStrictParsing("3.11.0", ""))
	assert.False(t, logrotateStrictParsing("3.14.0", ""))
	assert.False(t, logrotateStrictParsing("3.14.0", "4.el8"))
	assert.True(t, logrotateStrictParsing("3.14.0", "6.el8"))
	assert.True(t, logrotateStrictParsing("3.18.0", ""))
	assert.True(t, logrotateStrictParsing("3.22.0", ""))
	assert.False(t, logrotateStrictParsing("", ""))
}

func TestLogrotateFileHasCRLF(t *testing.T) {
	assert.True(t, logrotateFileHasCRLF("/var/log/g04/crlf.log {\r\n    weekly\r\n    rotate 3\r\n}\r\n"))
	assert.False(t, logrotateFileHasCRLF("/var/log/g04/x.log {\n    weekly\n}\n"))
	// a carriage return in a comment is no syntax error
	assert.False(t, logrotateFileHasCRLF("# written on windows\r\n/var/log/x {\n weekly\n}\n"))
}
