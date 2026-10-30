// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package squid

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigFromArgs(t *testing.T) {
	// /proc/1/cmdline of ubuntu/squid started with -f /opt/alt.conf -NYC
	assert.Equal(t, "/opt/alt.conf", ConfigFromArgs([]string{"-f", "/opt/alt.conf", "-NYC"}))
	// the ubuntu/squid image's own Cmd
	assert.Equal(t, "/etc/squid/squid.conf", ConfigFromArgs([]string{"-f", "/etc/squid/squid.conf", "-NYC"}))
	// RHEL 9 squid.service: --foreground $SQUID_OPTS -f ${SQUID_CONF}
	assert.Equal(t, "/etc/squid/squid.conf", ConfigFromArgs([]string{"--foreground", "-f", "/etc/squid/squid.conf"}))

	assert.Equal(t, "/etc/squid/a.conf", ConfigFromArgs([]string{"-f/etc/squid/a.conf"}), "attached argument")
	assert.Equal(t, "/etc/squid/b.conf", ConfigFromArgs([]string{"-NYCf", "/etc/squid/b.conf"}), "grouped flags")
	assert.Equal(t, "/etc/squid/c.conf", ConfigFromArgs([]string{"-f", "/x.conf", "-f", "/etc/squid/c.conf"}), "the last -f wins")
	assert.Equal(t, "/etc/squid/d.conf", ConfigFromArgs([]string{"-n", "-f", "-f", "/etc/squid/d.conf"}), "-n consumes the next word, even one that looks like an option")
	assert.Equal(t, "/etc/squid/e.conf", ConfigFromArgs([]string{"-mf", "-f", "/etc/squid/e.conf"}), "-m's attached argument is not -f")
	assert.Equal(t, "/etc/squid/g.conf", ConfigFromArgs([]string{"-d", "1", "-f", "/etc/squid/g.conf"}))

	// Debian and Ubuntu squid.service: --foreground -sYC
	assert.Equal(t, "", ConfigFromArgs([]string{"--foreground", "-sYC"}))
	assert.Equal(t, "", ConfigFromArgs([]string{"--kid", "squid-1", "--foreground", "-sYC"}))
	assert.Equal(t, "", ConfigFromArgs([]string{"-f"}), "a missing argument")
	assert.Equal(t, "", ConfigFromArgs([]string{"--", "-f", "/x"}))
	assert.Equal(t, "", ConfigFromArgs(nil))
}
