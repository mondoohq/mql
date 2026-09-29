// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/processes"
)

// Solaris 11.4 ships an /etc/os-release and so lands in the linux family, but
// its SVR4 ps rejects the BSD-style "axo" cluster the linux branch uses:
//
//	ps: illegal option -- o
//	usage: ps [ -aceglnrSuUvwx ] [ -t term ] ...
//
// Both fixtures below are verbatim from an Oracle Solaris 11.4.86 instance.
func solarisMock(t *testing.T) *mock.Connection {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "solaris",
			Family: []string{"linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"ps axo pid,pcpu,pmem,vsz,rss,tty,stat,stime,time,uid,command": {
				Stderr:     "ps: illegal option -- o\nusage: ps [ -aceglnrSuUvwx ] [ -t term ] [ --scale[=item1,item2,...] ] [ num ]",
				ExitStatus: 1,
			},
			"ps -eo pid,pcpu,pmem,vsz,rss,tty,s,time,uid,args": {
				Stdout: "  PID %CPU %MEM   VSZ      RSS TT      S        TIME   UID COMMAND\n" +
					"    0  0.2  0.0     0        0 ?       T       00:02     0 sched\n" +
					"    1  0.0  0.1  4952     4008 ?       S       00:00     0 /usr/sbin/init\n" +
					"    6  0.8  0.0     0        0 ?       S       00:03     0 zpool-rpool\n" +
					"  892  0.0  0.2 12140     6788 ?       S       00:00    54 /usr/lib/ssh/sshd\n",
			},
		},
	}))
	require.NoError(t, err)
	return conn
}

func TestSolarisProcessList(t *testing.T) {
	pm, err := processes.ResolveManager(solarisMock(t))
	require.NoError(t, err)
	require.NotNil(t, pm)

	list, err := pm.List()
	require.NoError(t, err, "solaris must not fall through to the BSD ps syntax")
	require.NotNil(t, list)
	require.Len(t, list, 4, "a running solaris host reports its processes")

	byPid := map[int64]*processes.OSProcess{}
	for _, p := range list {
		byPid[p.Pid] = p
	}

	init := byPid[1]
	require.NotNil(t, init)
	assert.Equal(t, "init", init.Executable)
	assert.Equal(t, "/usr/sbin/init", init.Command)
	assert.Equal(t, "S (sleeping)", init.State)

	sched := byPid[0]
	require.NotNil(t, sched)
	assert.Equal(t, "T (stopped)", sched.State)

	sshd := byPid[892]
	require.NotNil(t, sshd)
	assert.Equal(t, "sshd", sshd.Executable)
	assert.Equal(t, "/usr/lib/ssh/sshd", sshd.Command)
}
