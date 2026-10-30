// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cassandraconf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// RHEL 9, Cassandra 5.0.9, JVM_EXTRA_OPTS="-Dcassandra.config=file:///etc/cassandra/alt.yaml"
// in /etc/default/cassandra. The server logs "Configuration location:
// file:/etc/cassandra/alt.yaml".
func TestConfigFromJVMArgs(t *testing.T) {
	argv := []string{"/usr/lib/jvm/jre/bin/java", "-ea", "-Xms1G", "-Dcassandra.config=file:///etc/cassandra/alt.yaml",
		"-Dcassandra-pidfile=/var/run/cassandra/cassandra.pid", "-cp", "/etc/cassandra/conf:/usr/share/cassandra/lib/*",
		"org.apache.cassandra.service.CassandraDaemon"}
	conf, ok := ConfigFromJVMArgs(argv)
	assert.True(t, ok)
	assert.Equal(t, "/etc/cassandra/alt.yaml", conf)

	for in, want := range map[string]string{
		"-Dcassandra.config=file:/etc/cassandra/x.yaml": "/etc/cassandra/x.yaml",
		"-Dcassandra.config=/etc/cassandra/y.yaml":      "/etc/cassandra/y.yaml",
		"-Dcassandra.config=http://cfg.example/c.yaml":  "",
		"-Dcassandra.config=relative.yaml":              "",
	} {
		got, ok := ConfigFromJVMArgs([]string{"java", in, "org.apache.cassandra.service.CassandraDaemon"})
		assert.True(t, ok)
		assert.Equal(t, want, got, in)
	}

	_, ok = ConfigFromJVMArgs([]string{"java", "-Dcassandra.config=file:///x.yaml", "org.apache.cassandra.tools.NodeTool"})
	assert.False(t, ok, "nodetool is not the daemon")
	conf, ok = ConfigFromJVMArgs([]string{"java", "org.apache.cassandra.service.CassandraDaemon"})
	assert.True(t, ok)
	assert.Empty(t, conf)
}
