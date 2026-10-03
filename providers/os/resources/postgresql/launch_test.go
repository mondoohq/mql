// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package postgresql

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Postmaster command lines as /proc/<pid>/cmdline shows them on the sweep
// hosts: RHEL 7 (started by pg_ctl with -o "-p ${PGPORT}"), RHEL 9 and
// AlmaLinux 10 with the PGDG 17 packages. Debian's pg_ctlcluster passes
// config_file because the configuration lives under /etc/postgresql.
func TestParsePostmasterArgs(t *testing.T) {
	inst, ok := ParsePostmasterArgs([]string{"/usr/bin/postgres", "-D", "/var/lib/pgsql/data", "-p", "5432"})
	require.True(t, ok)
	assert.Equal(t, "/var/lib/pgsql/data", inst.DataDir)
	assert.Equal(t, "5432", inst.Settings["port"])
	assert.Equal(t, "/var/lib/pgsql/data/postgresql.conf", inst.ConfigFile())

	inst, ok = ParsePostmasterArgs([]string{"/usr/bin/postmaster", "-D", "/var/lib/pgsql/data"})
	require.True(t, ok)
	assert.Equal(t, "/var/lib/pgsql/data/postgresql.conf", inst.ConfigFile())
	assert.Empty(t, inst.Settings["port"])

	// PGDG's unit passes PGDATA with a trailing slash.
	inst, ok = ParsePostmasterArgs([]string{"/usr/pgsql-17/bin/postgres", "-D", "/var/lib/pgsql/17/data/"})
	require.True(t, ok)
	assert.Equal(t, "/var/lib/pgsql/17/data/postgresql.conf", inst.ConfigFile())

	inst, ok = ParsePostmasterArgs([]string{
		"/usr/lib/postgresql/16/bin/postgres", "-D", "/var/lib/postgresql/16/main",
		"-c", "config_file=/etc/postgresql/16/main/postgresql.conf",
	})
	require.True(t, ok)
	assert.Equal(t, "/etc/postgresql/16/main/postgresql.conf", inst.ConfigFile())

	// Attached values, long options and an option argument that looks like
	// a flag.
	inst, ok = ParsePostmasterArgs([]string{"postgres", "-D/srv/pg", "-p5433", "--hba-file=/etc/pg/hba.conf", "-c", "Port=5434", "-k", "-p"})
	require.True(t, ok)
	assert.Equal(t, "/srv/pg", inst.DataDir)
	assert.Equal(t, "5434", inst.Settings["port"], "the last port setting wins")
	assert.Equal(t, "/etc/pg/hba.conf", inst.Settings["hba_file"])
}

// Backends rewrite argv[0]; only the postmaster names the binary.
func TestParsePostmasterArgsSkipsOtherProcesses(t *testing.T) {
	for _, argv := range [][]string{
		{"postgres: checkpointer "},
		{"postgres: logger "},
		{"/usr/bin/pg_ctl", "start", "-D", "/var/lib/pgsql/data"},
		{"/usr/bin/psql", "-p", "5432"},
		{},
	} {
		_, ok := ParsePostmasterArgs(argv)
		assert.False(t, ok, "%q", argv)
	}
}

// `systemctl show -p Id -p Environment -p ExecStart 'postgresql*.service'`
// on RHEL 7 and on AlmaLinux 10 with PGDG 17, plus a Debian pg_ctlcluster
// unit that names no data directory.
const systemctlShowRhel7 = `ExecStart={ path=/usr/bin/pg_ctl ; argv[]=/usr/bin/pg_ctl start -D ${PGDATA} -s -o -p ${PGPORT} -w -t 300 ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
Environment=PGPORT=5432 PGDATA=/var/lib/pgsql/data
Id=postgresql.service
`

const systemctlShowPgdg = `ExecStart={ path=/usr/pgsql-17/bin/postgres ; argv[]=/usr/pgsql-17/bin/postgres -D ${PGDATA} ; ignore_errors=no ; start_time=[Fri 2026-10-02 10:08:27 UTC] ; stop_time=[n/a] ; pid=140056 ; code=(null) ; status=0/0 }
Environment=PGDATA=/var/lib/pgsql/17/data/ PG_OOM_ADJUST_FILE=/proc/self/oom_score_adj PG_OOM_ADJUST_VALUE=0
Id=postgresql-17.service

ExecStart={ path=/usr/bin/pg_ctlcluster ; argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect 16-main start ; ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
Environment=
Id=postgresql@16-main.service
`

func TestParseSystemctlShow(t *testing.T) {
	units := ParseSystemctlShow(systemctlShowRhel7)
	require.Len(t, units, 1)
	assert.Equal(t, "postgresql.service", units[0].ID)
	assert.Equal(t, map[string]string{"PGPORT": "5432", "PGDATA": "/var/lib/pgsql/data"}, units[0].Environment)
	assert.Equal(t, []string{"/usr/bin/pg_ctl", "start", "-D", "${PGDATA}", "-s", "-o", "-p", "${PGPORT}", "-w", "-t", "300"}, units[0].ExecStart)

	units = ParseSystemctlShow(systemctlShowPgdg)
	require.Len(t, units, 2)
	assert.Equal(t, "postgresql-17.service", units[0].ID)
	assert.Equal(t, "/var/lib/pgsql/17/data/", units[0].Environment["PGDATA"])
	assert.Equal(t, "postgresql@16-main.service", units[1].ID)
	assert.Empty(t, units[1].Environment)

	units = ParseSystemctlShow(`Environment="PGDATA=/srv/pg data" PGPORT=5433` + "\nId=postgresql.service\n")
	require.Len(t, units, 1)
	assert.Equal(t, "/srv/pg data", units[0].Environment["PGDATA"])
	assert.Equal(t, "5433", units[0].Environment["PGPORT"])
}

func TestUnitInstance(t *testing.T) {
	// RHEL 7: the unit forces the port on the command line.
	inst, ok := UnitInstance(ParseSystemctlShow(systemctlShowRhel7)[0])
	require.True(t, ok)
	assert.Equal(t, "/var/lib/pgsql/data", inst.DataDir)
	assert.Equal(t, "5432", inst.Settings["port"])
	assert.Equal(t, "5432", inst.Env["PGPORT"])

	units := ParseSystemctlShow(systemctlShowPgdg)
	inst, ok = UnitInstance(units[0])
	require.True(t, ok)
	assert.Equal(t, "/var/lib/pgsql/17/data/postgresql.conf", inst.ConfigFile())
	assert.Empty(t, inst.Settings["port"], "the PGDG unit does not pass a port")

	_, ok = UnitInstance(units[1])
	assert.False(t, ok, "a pg_ctlcluster unit names no data directory")

	// pg_ctl's own -p is the path of the postgres binary, not a port.
	inst, ok = UnitInstance(Unit{
		Environment: map[string]string{"PGDATA": "/srv/pg"},
		ExecStart:   []string{"/usr/bin/pg_ctl", "start", "-D", "${PGDATA}", "-p", "/usr/bin/postgres"},
	})
	require.True(t, ok)
	assert.Empty(t, inst.Settings["port"])

	// A drop-in that relocates PGDATA and passes the port with -c.
	inst, ok = UnitInstance(Unit{
		Environment: map[string]string{"PGDATA": "/srv/pgdata", "PGPORT": "5433"},
		ExecStart:   []string{"/usr/bin/postmaster", "-D", "$PGDATA", "-c", "port=6000"},
	})
	require.True(t, ok)
	assert.Equal(t, "/srv/pgdata/postgresql.conf", inst.ConfigFile())
	assert.Equal(t, "6000", inst.Settings["port"])
}

// PostgreSQL's precedence: command line, then postgresql.conf, then PGPORT,
// then 5432.
func TestEffectivePort(t *testing.T) {
	rhel7 := &Instance{Settings: map[string]string{"port": "5432"}, Env: map[string]string{"PGPORT": "5432"}}
	assert.Equal(t, int64(5432), EffectivePort("5433", rhel7), "-p overrides the file")

	envOnly := &Instance{Settings: map[string]string{}, Env: map[string]string{"PGPORT": "5440"}}
	assert.Equal(t, int64(5433), EffectivePort("5433", envOnly), "the file overrides PGPORT")
	assert.Equal(t, int64(5440), EffectivePort("", envOnly), "PGPORT applies when the file is silent")

	assert.Equal(t, int64(5433), EffectivePort("5433", nil))
	assert.Equal(t, int64(5432), EffectivePort("", nil))
	assert.Equal(t, int64(5432), EffectivePort("not-a-port", nil))
}

func TestInstanceFor(t *testing.T) {
	running := []Instance{
		{DataDir: "/var/lib/pgsql/data", Settings: map[string]string{"port": "5432"}},
	}
	units := []Instance{
		{DataDir: "/var/lib/pgsql/17/data", Settings: map[string]string{}, Env: map[string]string{"PGPORT": "5440"}},
		{DataDir: "/var/lib/pgsql/data", Settings: map[string]string{"port": "5999"}, Env: map[string]string{"PGPORT": "5999"}},
	}

	inst := InstanceFor("/var/lib/pgsql/data/postgresql.conf", running, units)
	require.NotNil(t, inst)
	assert.Equal(t, "5432", inst.Settings["port"], "the running command line wins over the unit's")
	assert.Equal(t, "5999", inst.Env["PGPORT"], "the environment comes from the unit")

	inst = InstanceFor("/var/lib/pgsql/17/data/postgresql.conf", running, units)
	require.NotNil(t, inst)
	assert.Equal(t, "5440", inst.Env["PGPORT"])

	assert.Nil(t, InstanceFor("/etc/postgresql/16/main/postgresql.conf", running, units))
}

func TestAuxFilePath(t *testing.T) {
	const rhelConf = "/var/lib/pgsql/data/postgresql.conf"
	assert.Equal(t, "/var/lib/pgsql/data/pg_hba.conf",
		AuxFilePath(rhelConf, map[string]string{}, "hba_file", "pg_hba.conf"))
	assert.Equal(t, "/etc/pgsql/sweep_hba.conf",
		AuxFilePath(rhelConf, map[string]string{"hba_file": "/etc/pgsql/sweep_hba.conf"}, "hba_file", "pg_hba.conf"))
	assert.Equal(t, "/var/lib/pgsql/data/auth/ident.conf",
		AuxFilePath(rhelConf, map[string]string{"ident_file": "auth/ident.conf"}, "ident_file", "pg_ident.conf"))

	// Debian keeps postgresql.conf under /etc and the data elsewhere.
	const debConf = "/etc/postgresql/16/main/postgresql.conf"
	assert.Equal(t, "/etc/postgresql/16/main/pg_hba.conf",
		AuxFilePath(debConf, map[string]string{
			"data_directory": "/var/lib/postgresql/16/main",
			"hba_file":       "/etc/postgresql/16/main/pg_hba.conf",
		}, "hba_file", "pg_hba.conf"))
	assert.Equal(t, "/var/lib/postgresql/16/main/pg_ident.conf",
		AuxFilePath(debConf, map[string]string{"data_directory": "/var/lib/postgresql/16/main"}, "ident_file", "pg_ident.conf"),
		"without ident_file the server reads the data directory's pg_ident.conf")
}

// systemctlShowSuse is `systemctl show -p Id -p Environment -p
// EnvironmentFiles -p ExecStart postgresql.service` on SLES 15 SP7.
const systemctlShowSuse = `ExecStart={ path=/usr/share/postgresql/postgresql-script ; argv[]=/usr/share/postgresql/postgresql-script start ; ignore_errors=no ; start_time=[Fri 2026-10-02 14:44:35 UTC] ; stop_time=[Fri 2026-10-02 14:44:35 UTC] ; pid=21252 ; code=exited ; status=0 }
Environment=
EnvironmentFiles=/etc/sysconfig/postgresql (ignore_errors=yes)
Id=postgresql.service
`

// suseSysconfig is the shipped /etc/sysconfig/postgresql of SLES 15 SP7, its
// comments left out, with the data directory and options to use.
func suseSysconfig(datadir, options string) string {
	return `## Path:	   Applications/PostgreSQL
## Default:	   "~postgres/data"
POSTGRES_DATADIR="` + datadir + `"
## Default:        ""
POSTGRES_OPTIONS="` + options + `"
POSTGRES_TIMEOUT="600"
POSTGRES_LANG=""
POSTGRES_INITDB_OPTS="--auth=ident"
POSTGRES_DEFAULTVERSION=""
`
}

func TestSuseUnitInstance(t *testing.T) {
	suseHomes := map[string]string{"postgres": "/var/lib/pgsql"}
	suseUnit := func(sysconfig string) Unit {
		u := ParseSystemctlShow(systemctlShowSuse)[0]
		if sysconfig != "" {
			u.ApplyEnvironmentFile(sysconfig)
		}
		u.Homes = suseHomes
		return u
	}

	units := ParseSystemctlShow(systemctlShowSuse)
	require.Len(t, units, 1)
	assert.Equal(t, []string{"/etc/sysconfig/postgresql"}, units[0].EnvironmentFiles)
	assert.Empty(t, units[0].Environment, "the unit sets nothing inline")
	assert.True(t, units[0].IsSuseStartScript())
	assert.False(t, ParseSystemctlShow(systemctlShowRhel7)[0].IsSuseStartScript())

	// stock: ~postgres/data is the postgres home's data directory
	inst, ok := UnitInstance(suseUnit(suseSysconfig("~postgres/data", "")))
	require.True(t, ok)
	assert.Equal(t, "/var/lib/pgsql/data/postgresql.conf", inst.ConfigFile())
	assert.Empty(t, inst.Settings["port"])

	// no sysconfig file: the script's own default
	inst, ok = UnitInstance(suseUnit(""))
	require.True(t, ok)
	assert.Equal(t, "/var/lib/pgsql/data/postgresql.conf", inst.ConfigFile())

	// relocated, with the port passed through pg_ctl -o
	inst, ok = UnitInstance(suseUnit(suseSysconfig("/var/lib/pgsql/reloc/data", "-p 5433")))
	require.True(t, ok)
	assert.Equal(t, "/var/lib/pgsql/reloc/data/postgresql.conf", inst.ConfigFile())
	assert.Equal(t, "5433", inst.Settings["port"])
	assert.Equal(t, int64(5433), EffectivePort("5432", &inst), "the command line beats the file")

	// config_file given among the options
	inst, ok = UnitInstance(suseUnit(suseSysconfig("~postgres/data", "-c config_file=/etc/pgsql/sweep.conf --port=6000")))
	require.True(t, ok)
	assert.Equal(t, "/etc/pgsql/sweep.conf", inst.ConfigFile())
	assert.Equal(t, "6000", inst.Settings["port"])
	assert.Equal(t, "/var/lib/pgsql/data", inst.DataDir)

	// a home that is not known yields no cluster rather than a guess
	u := suseUnit(suseSysconfig("~postgres/data", ""))
	u.Homes = nil
	_, ok = UnitInstance(u)
	assert.False(t, ok)
}

func TestApplyEnvironmentFileOverridesEnvironment(t *testing.T) {
	u := ParseSystemctlShow(systemctlShowRhel7)[0]
	u.ApplyEnvironmentFile("PGDATA=/srv/pgdata\n")
	inst, ok := UnitInstance(u)
	require.True(t, ok)
	assert.Equal(t, "/srv/pgdata", inst.DataDir)
	assert.Equal(t, "5432", inst.Env["PGPORT"], "Environment= stays for what the file does not set")
}

func TestApplyEnv(t *testing.T) {
	// postgres:13-alpine runs `postgres -c log_connections=on ...` with
	// PGDATA from the image
	inst, ok := ParsePostmasterArgs([]string{"postgres", "-c", "log_connections=on"})
	assert.True(t, ok)
	assert.Equal(t, "", inst.ConfigFile())
	inst.ApplyEnv(map[string]string{"PGDATA": "/var/lib/postgresql/data/"})
	assert.Equal(t, "/var/lib/postgresql/data/postgresql.conf", inst.ConfigFile())
	assert.Equal(t, "/var/lib/postgresql/data/", inst.Env["PGDATA"])

	inst, _ = ParsePostmasterArgs([]string{"postgres", "-D", "/srv/pg"})
	inst.ApplyEnv(map[string]string{"PGDATA": "/var/lib/postgresql/data"})
	assert.Equal(t, "/srv/pg", inst.DataDir, "-D wins over PGDATA")
}

func TestParsePostmasterPid(t *testing.T) {
	// postmaster.pid of the postgres:13-alpine container
	pid, ok := ParsePostmasterPid("1\n/var/lib/postgresql/data\n1791032192\n5432\n/var/run/postgresql\n127.0.0.1\n   278037         5\nready   \n")
	assert.True(t, ok)
	assert.Equal(t, 1, pid)
	_, ok = ParsePostmasterPid("")
	assert.False(t, ok)
	_, ok = ParsePostmasterPid("-1\n")
	assert.False(t, ok)
}

func TestOverlay(t *testing.T) {
	file := map[string]string{"listen_addresses": "*", "log_connections": "off", "port": "5432"}
	inst, _ := ParsePostmasterArgs([]string{"postgres", "-c", "log_connections=on", "--password-encryption=md5", "-p", "5433"})
	got := Overlay(file, &inst)
	assert.Equal(t, "on", got["log_connections"])
	assert.Equal(t, "md5", got["password_encryption"], "the long form, with dashes, names the same setting")
	assert.Equal(t, "5433", got["port"])
	assert.Equal(t, "*", got["listen_addresses"], "settings the command line does not give stay")
	assert.Equal(t, "off", file["log_connections"], "the file's own map is not changed")
	assert.Equal(t, file, Overlay(file, nil))
}

func TestRunningByPid(t *testing.T) {
	running := []Instance{{Pid: 7}, {Pid: 1, Settings: map[string]string{"log_connections": "on"}}}
	assert.Equal(t, "on", RunningByPid(running, 1).Settings["log_connections"])
	assert.Nil(t, RunningByPid(running, 2))
}

func TestDataDirectory(t *testing.T) {
	assert.Equal(t, "/var/lib/postgresql/data", DataDirectory("/var/lib/postgresql/data/postgresql.conf", nil))
	assert.Equal(t, "/var/lib/postgresql/17/main", DataDirectory("/etc/postgresql/17/main/postgresql.conf", map[string]string{"data_directory": "/var/lib/postgresql/17/main/"}))
	assert.Equal(t, "/etc/pg/data", DataDirectory("/etc/pg/postgresql.conf", map[string]string{"data_directory": "data"}), "relative to the file's directory")
}
