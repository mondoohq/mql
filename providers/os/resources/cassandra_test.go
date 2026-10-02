// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCassandraVersionCommands(t *testing.T) {
	// The Debian and RPM packages install the launch script as
	// /usr/sbin/cassandra (Debian 9 to 13 with Cassandra 3.11.19 to 5.0.9,
	// RHEL 9 with 5.0.9), which is not on a non-root user's PATH
	// (/usr/local/bin:/usr/bin:/bin:/usr/games on Debian), so it is probed
	// by absolute path. The tarball layout keeps the launch script next to the conf
	// directory: /opt/cassandra/conf and /opt/cassandra/bin/cassandra
	// (Apache Cassandra 4.1.12 unpacked under /opt on RHEL 7, which puts
	// nothing on PATH). Package layouts install `cassandra` on PATH, so
	// /etc/cassandra yields no sibling binary.
	assert.Equal(t, []string{
		"/usr/sbin/cassandra",
		"/usr/bin/cassandra",
		"/opt/cassandra/bin/cassandra",
		"/usr/local/cassandra/bin/cassandra",
	}, cassandraBinaries([]string{
		"/etc/cassandra",
		"/etc/cassandra/conf",
		"/opt/cassandra/conf",
		"/usr/local/cassandra/conf",
		"/opt/homebrew/etc/cassandra",
	}))
}
