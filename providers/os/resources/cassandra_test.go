// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCassandraVersionCommands(t *testing.T) {
	// The tarball layout keeps the launch script next to the conf
	// directory: /opt/cassandra/conf and /opt/cassandra/bin/cassandra
	// (Apache Cassandra 4.1.12 unpacked under /opt on RHEL 7, which puts
	// nothing on PATH). Package layouts install `cassandra` on PATH, so
	// /etc/cassandra yields no sibling binary.
	assert.Equal(t, []string{
		"/opt/cassandra/bin/cassandra",
		"/usr/local/cassandra/bin/cassandra",
	}, cassandraTarballBinaries([]string{
		"/etc/cassandra",
		"/etc/cassandra/conf",
		"/opt/cassandra/conf",
		"/usr/local/cassandra/conf",
		"/opt/homebrew/etc/cassandra",
	}))
}
