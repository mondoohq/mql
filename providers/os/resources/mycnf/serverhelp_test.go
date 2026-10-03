// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mycnf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Headers of `--verbose --help` captured on the sweep hosts.
func TestParseServerHelp(t *testing.T) {
	for _, tc := range []struct {
		name, output  string
		files, groups []string
	}{
		{
			name: "Fedora 44, MariaDB 11.8.8",
			output: "/usr/sbin/mariadbd  Ver 11.8.8-MariaDB-log for Linux on x86_64 (MariaDB Server)\n" +
				"Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.\n\n" +
				"Default options are read from the following files in the given order:\n" +
				"/etc/my.cnf ~/.my.cnf \n" +
				"The following groups are read: mysqld server mysqld-11.8 mariadb mariadb-11.8 mariadb-11 mariadbd mariadbd-11.8 mariadbd-11 client-server galera\n" +
				"The following options may be given as the first argument:\n",
			files:  []string{"/etc/my.cnf", "~/.my.cnf"},
			groups: []string{"mysqld", "server", "mysqld-11.8", "mariadb", "mariadb-11.8", "mariadb-11", "mariadbd", "mariadbd-11.8", "mariadbd-11", "client-server", "galera"},
		},
		{
			// Built without wsrep: no [galera].
			name: "Amazon Linux 2023, mariadb123 12.3.2",
			output: "Default options are read from the following files in the given order:\n" +
				"/etc/my.cnf ~/.my.cnf \n" +
				"The following groups are read: mysqld server mysqld-12.3 mariadb mariadb-12.3 mariadb-12 mariadbd mariadbd-12.3 mariadbd-12 client-server\n",
			files:  []string{"/etc/my.cnf", "~/.my.cnf"},
			groups: []string{"mysqld", "server", "mysqld-12.3", "mariadb", "mariadb-12.3", "mariadb-12", "mariadbd", "mariadbd-12.3", "mariadbd-12", "client-server"},
		},
		{
			name: "openSUSE Leap 16, Oracle MySQL 26.7.0",
			output: "/usr/sbin/mysqld  Ver 26.7.0 for Linux on x86_64 (MySQL Community Server - GPL)\n" +
				"Default options are read from the following files in the given order:\n" +
				"/etc/my.cnf /etc/mysql/my.cnf /usr/etc/my.cnf ~/.my.cnf \n" +
				"The following groups are read: mysql_cluster mysqld server mysqld-26.7\n",
			files:  []string{"/etc/my.cnf", "/etc/mysql/my.cnf", "/usr/etc/my.cnf", "~/.my.cnf"},
			groups: []string{"mysql_cluster", "mysqld", "server", "mysqld-26.7"},
		},
		{
			name: "CentOS Stream 9, Percona Server 8.0.46",
			output: "Default options are read from the following files in the given order:\r\n" +
				"/etc/my.cnf /etc/mysql/my.cnf /usr/etc/my.cnf ~/.my.cnf \r\n" +
				"The following groups are read: mysql_cluster mysqld server mysqld-8.0\r\n",
			files:  []string{"/etc/my.cnf", "/etc/mysql/my.cnf", "/usr/etc/my.cnf", "~/.my.cnf"},
			groups: []string{"mysql_cluster", "mysqld", "server", "mysqld-8.0"},
		},
		{
			name: "RHEL 9, AppStream MySQL 8.0.46",
			output: "Default options are read from the following files in the given order:\n" +
				"/etc/my.cnf /etc/mysql/my.cnf ~/.my.cnf \n" +
				"The following groups are read: mysqld server mysqld-8.0\n",
			files:  []string{"/etc/my.cnf", "/etc/mysql/my.cnf", "~/.my.cnf"},
			groups: []string{"mysqld", "server", "mysqld-8.0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, ok := ParseServerHelp(tc.output)
			require.True(t, ok)
			assert.Equal(t, tc.files, d.Files)
			assert.Equal(t, tc.groups, d.Groups)
		})
	}

	_, ok := ParseServerHelp("mysqld: unknown option '--verbose'\n")
	assert.False(t, ok)
}

// Debian 12, MySQL 8.4.11 after SET PERSIST local_infile=ON,
// max_connections=333, require_secure_transport=ON and SET PERSIST_ONLY
// skip_name_resolve=ON. After a restart the server runs ON/333/ON/ON with
// variables_info source PERSISTED, even with --max-connections=444 on its
// command line.
const persistedV2 = `{"Version": 2, "mysql_static_variables": {"skip_name_resolve": {"Value": "ON", "Metadata": {"Host": "localhost", "User": "root", "Timestamp": 1790994956910939}}}, "mysql_dynamic_variables": {"local_infile": {"Value": "ON", "Metadata": {"Host": "localhost", "User": "root", "Timestamp": 1790994956901229}}, "require_secure_transport": {"Value": "ON", "Metadata": {"Host": "localhost", "User": "root", "Timestamp": 1790994956907713}}}, "mysql_dynamic_parse_early_variables": {"max_connections": {"Value": "333", "Metadata": {"Host": "localhost", "User": "root", "Timestamp": 1790994956904499}}}}`

func TestParsePersisted(t *testing.T) {
	opts, err := ParsePersisted(persistedV2)
	require.NoError(t, err)
	got := map[string]string{}
	for _, o := range opts {
		got[o.Name] = o.Value
	}
	assert.Equal(t, map[string]string{
		"local_infile": "ON", "max_connections": "333", "require_secure_transport": "ON", "skip_name_resolve": "ON",
	}, got)
}

// The 8.0.x layout before version 2.
func TestParsePersistedV1(t *testing.T) {
	opts, err := ParsePersisted(`{ "Version" : 1 , "mysql_server" : { "max_connections" : { "Value" : "333" , "Metadata" : { "Timestamp" : 1 , "User" : "root" , "Host" : "localhost" } } , "mysql_server_static_options" : { "skip_name_resolve" : { "Value" : "ON" , "Metadata" : { "Timestamp" : 1 , "User" : "root" , "Host" : "localhost" } } } } }`)
	require.NoError(t, err)
	require.Len(t, opts, 2)
	assert.Equal(t, Option{Name: "max_connections", Value: "333"}, opts[0])
	assert.Equal(t, Option{Name: "skip_name_resolve", Value: "ON"}, opts[1])
}

func TestParsePersistedEmptyAndBroken(t *testing.T) {
	opts, err := ParsePersisted(`{"Version": 2}`)
	require.NoError(t, err)
	assert.Empty(t, opts)
	_, err = ParsePersisted(`{"Version": 2, "mysql_dynamic_variables": `)
	assert.Error(t, err)
}
