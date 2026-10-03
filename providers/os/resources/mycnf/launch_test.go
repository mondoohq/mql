// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mycnf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The command line of a Debian 12 MySQL 8.4 server started by a drop-in with
// ExecStart=/usr/sbin/mysqld --defaults-file=/etc/mysql/alt.cnf.
func TestParseServerArgsDefaultsFile(t *testing.T) {
	launch, ok := ParseServerArgs([]string{"/usr/sbin/mysqld", "--defaults-file=/etc/mysql/alt.cnf"})
	require.True(t, ok)
	assert.Equal(t, "mysqld", launch.Binary)
	assert.Equal(t, "/etc/mysql/alt.cnf", launch.DefaultsFile)
	assert.False(t, launch.NoDefaults)
	assert.Empty(t, launch.Options)
}

func TestParseServerArgsOptionFileArguments(t *testing.T) {
	launch, ok := ParseServerArgs([]string{
		"/usr/sbin/mariadbd", "--no-defaults", "--defaults-extra-file=/etc/mysql/extra.cnf",
		"--defaults-group-suffix=_eu", "--port=3307",
	})
	require.True(t, ok)
	assert.Equal(t, "mariadbd", launch.Binary)
	assert.True(t, launch.NoDefaults)
	assert.Equal(t, "_eu", launch.GroupSuffix)
	assert.Empty(t, launch.ExtraFile, "--no-defaults reads no file, extra file included")
	require.Len(t, launch.Options, 1)
	assert.Equal(t, "port", launch.Options[0].Name)
}

// The server honors the option file arguments only at the front of its
// command line; after another option it refuses them, so they never describe
// a running server there.
func TestParseServerArgsOptionFileArgumentsOnlyAtTheFront(t *testing.T) {
	launch, ok := ParseServerArgs([]string{"/usr/sbin/mysqld", "--port=3307", "--defaults-file=/etc/mysql/alt.cnf"})
	require.True(t, ok)
	assert.Empty(t, launch.DefaultsFile)
}

// Oracle MySQL 5.7's unit on Debian 9 starts the server with --daemonize and
// --pid-file. Both are server options that override the option files.
func TestParseServerArgsOverrides(t *testing.T) {
	launch, ok := ParseServerArgs([]string{
		"/usr/sbin/mysqld", "--daemonize", "--pid-file=/var/run/mysqld/mysqld.pid",
		"--bind-address=0.0.0.0", "--enable-local-infile", "--skip-name-resolve=0", "-u", "mysql", "--", "--port=1",
	})
	require.True(t, ok)

	conf := &Conf{Options: []Option{
		{Section: "mysqld", Name: "bind_address", Value: "127.0.0.1"},
		{Section: "mysqld", Name: "local_infile", Value: "0"},
		{Section: "mysqld", Name: "skip_name_resolve", Bare: true},
		{Section: "mysqld", Name: "max_connections", Value: "120"},
		{Section: "mysqld_safe", Name: "port", Value: "4444"},
	}}
	merged := MergeWithArgs(conf, launch.Options, "mysqld", "server")
	assert.Equal(t, "0.0.0.0", merged["bind_address"])
	assert.Equal(t, "ON", merged["local_infile"])
	assert.Equal(t, "ON", merged["daemonize"])
	assert.Equal(t, "/var/run/mysqld/mysqld.pid", merged["pid_file"])
	assert.Equal(t, "120", merged["max_connections"], "options the command line does not set come from the files")
	assert.Equal(t, "0", merged["skip_name_resolve"], "skip-name-resolve=0 overrides the bare option in the file")
	assert.NotContains(t, merged, "port", "arguments after -- are not options, and [mysqld_safe] is not server scope")
	assert.NotContains(t, merged, "u")
}

func TestParseServerArgsRejectsOtherPrograms(t *testing.T) {
	for _, argv := range [][]string{
		{"/usr/bin/mysqld_safe", "--defaults-file=/etc/my.cnf"},
		{"/usr/bin/mongod", "--config", "/etc/mongod.conf"},
		{},
	} {
		_, ok := ParseServerArgs(argv)
		assert.False(t, ok, argv)
	}
}

func TestMergeWithArgsAccumulatesPluginLoadAdd(t *testing.T) {
	conf := &Conf{Options: []Option{{Section: "mariadbd", Name: "plugin_load_add", Value: "provider_lz4"}}}
	launch, _ := ParseServerArgs([]string{"/usr/sbin/mariadbd", "--plugin-load-add=server_audit"})
	merged := MergeWithArgs(conf, launch.Options, "mariadbd")
	assert.Equal(t, Merge(&Conf{Options: []Option{
		{Section: "x", Name: "plugin_load_add", Value: "provider_lz4"},
		{Section: "x", Name: "plugin_load_add", Value: "server_audit"},
	}}, "x")["plugin_load_add"], merged["plugin_load_add"])
	assert.Contains(t, merged["plugin_load_add"], "server_audit")
	assert.Contains(t, merged["plugin_load_add"], "provider_lz4")
}

func TestWithGroupSuffix(t *testing.T) {
	assert.Equal(t, []string{"mysqld", "server", "mysqld_eu", "server_eu"}, WithGroupSuffix([]string{"mysqld", "server"}, "_eu"))
	assert.Equal(t, []string{"mysqld"}, WithGroupSuffix([]string{"mysqld"}, ""))
}

// A --defaults-extra-file is read after the root file, so its options win.
func TestConfAppendReadsExtraFileLast(t *testing.T) {
	reader, dirLister := mapFS(map[string]string{
		"/etc/mysql/my.cnf":    "[mysqld]\nlocal_infile=0\nport=3306\n",
		"/etc/mysql/extra.cnf": "[mysqld]\nlocal_infile=1\n[galera]\n",
	})
	conf, err := Parse("/etc/mysql/my.cnf", reader, dirLister)
	require.NoError(t, err)
	extra, err := Parse("/etc/mysql/extra.cnf", reader, dirLister)
	require.NoError(t, err)
	conf.Append(extra)

	merged := Merge(conf, "mysqld")
	assert.Equal(t, "1", merged["local_infile"])
	assert.Equal(t, "3306", merged["port"])
	assert.Equal(t, []string{"/etc/mysql/my.cnf", "/etc/mysql/extra.cnf"}, conf.Files)
	assert.Contains(t, conf.SectionNames(), "galera")
}

// An option from a file can never be taken for a command line option, even
// one the parser filed under an empty group.
func TestMergeWithArgsKeepsFileOptionsOutOfTheCommandLine(t *testing.T) {
	conf := &Conf{Options: []Option{{Section: "", Name: "local_infile", Value: "1"}}}
	launch, _ := ParseServerArgs([]string{"/usr/sbin/mysqld", "--port=3307"})
	merged := MergeWithArgs(conf, launch.Options, "mysqld")
	assert.NotContains(t, merged, "local_infile")
	assert.Equal(t, "3307", merged["port"])
}

// ExecStart= of mariadb.service on openSUSE Leap 16 and SLES 16
// (MariaDB 11.8.8), and of an instance of mariadb@.service. The helper execs
// /usr/sbin/mysqld --defaults-file=/etc/my<instance>.cnf --user=mysql.
func TestParseSuseHelperArgs(t *testing.T) {
	launch, ok := ParseSuseHelperArgs([]string{"/usr/libexec/mysql/mysql-systemd-helper", "start"})
	require.True(t, ok)
	assert.Equal(t, "mysqld", launch.Binary)
	assert.Equal(t, "/etc/my.cnf", launch.DefaultsFile)
	assert.Equal(t, []Option{{Name: "user", Value: "mysql", Line: 1}}, launch.Options)

	launch, ok = ParseSuseHelperArgs([]string{"/usr/lib/mysql/mysql-systemd-helper", "start", "eu"})
	require.True(t, ok)
	assert.Equal(t, "/etc/myeu.cnf", launch.DefaultsFile)

	for _, argv := range [][]string{
		{"/usr/libexec/mysql/mysql-systemd-helper", "install"},
		{"/usr/libexec/mysql/mysql-systemd-helper"},
		{"/usr/sbin/mysqld", "start"},
	} {
		_, ok := ParseSuseHelperArgs(argv)
		assert.False(t, ok, argv)
	}
}
