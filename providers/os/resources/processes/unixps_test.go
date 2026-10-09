// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes_test

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/processes"
)

func TestLinuxPSProcessParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"linux"},
		},
	}, mock.WithPath("./testdata/debian.toml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := mock.RunCommand("ps axo pid,pcpu,pmem,vsz,rss,tty,stat,stime,time,uid,command")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)

	m, err := processes.ParseLinuxPsResult(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(m), "detected the right amount of processes")

	assert.Equal(t, "/bin/bash", m[0].Command, "process command detected")
	assert.Equal(t, int64(1), m[0].Pid, "process pid detected")
	assert.Equal(t, int64(0), m[0].Uid, "process uid detected")

	assert.Equal(t, "ps axo pid,pcpu,pmem,vsz,rss,tty,stat,stime,time,uid,command", m[1].Command, "process command detected")
	assert.Equal(t, int64(46), m[1].Pid, "process pid detected")
	assert.Equal(t, int64(0), m[1].Uid, "process uid detected")

	assert.Equal(t, "", m[2].Command, "process command matched against empty COMMAND column")
	assert.Equal(t, int64(3987), m[2].Pid, "process pid detected")
	assert.Equal(t, int64(0), m[2].Uid, "process uid detected")
}

func TestOSxPSProcessParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"unix"},
		},
	}, mock.WithPath("./testdata/osx.toml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := mock.RunCommand("ps Axo pid,pcpu,pmem,vsz,rss,tty,stat,stime,time,uid,command")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)

	m, err := processes.ParseLinuxPsResult(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 41, len(m), "detected the right amount of processes")

	assert.Equal(t, "/sbin/launchd", m[0].Command, "process command detected")
	assert.Equal(t, int64(1), m[0].Pid, "process pid detected")
	assert.Equal(t, int64(0), m[0].Uid, "process uid detected")

	assert.Equal(t, "/usr/sbin/syslogd", m[1].Command, "process command detected")
	assert.Equal(t, int64(125), m[1].Pid, "process pid detected")
	assert.Equal(t, int64(0), m[1].Uid, "process uid detected")
}

func TestUnixPSProcessParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"unix"},
		},
	}, mock.WithPath("./testdata/freebsd12.toml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := mock.RunCommand("ps axo pid,pcpu,pmem,vsz,rss,tty,stat,time,uid,command")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)

	m, err := processes.ParseUnixPsResult(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 41, len(m), "detected the right amount of processes")

	assert.Equal(t, "[kernel]", m[0].Command, "process command detected")
	assert.Equal(t, int64(0), m[0].Pid, "process pid detected")
	assert.Equal(t, int64(0), m[0].Uid, "process uid detected")

	assert.Equal(t, "[Timer]", m[20].Command, "process command detected")
	assert.Equal(t, int64(88), m[20].Pid, "process pid detected")
	assert.Equal(t, int64(0), m[20].Uid, "process uid detected")
}

func TestAixPSProcessParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "aix",
			Family: []string{"unix"},
		},
	}, mock.WithPath("./testdata/aix72.toml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := mock.RunCommand("ps -A -o pid,pcpu,pmem,vsz,tty,time,uid,args")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)

	m, err := processes.ParseAixPsResult(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 27, len(m), "detected the right amount of processes")

	// search ssh
	var found *processes.ProcessEntry
	for i := range m {
		if strings.HasPrefix(m[i].Command, "sshd") {
			found = m[i]
		}
	}

	assert.Equal(t, "sshd: cecuser [priv]", found.Command, "process command detected")
	assert.Equal(t, int64(3670308), found.Pid, "process pid detected")
	assert.Equal(t, int64(0), found.Uid, "process uid detected")
}

func TestAixPSProcessParser_NonNumericUid(t *testing.T) {
	// A row whose uid column is non-numeric hits the uid-parse-error branch.
	// That branch previously referenced m[9] — out of range for the 8-group
	// AIX regex — and panicked; it must now skip the row cleanly.
	input := " 1234 0.1 0.2 4096 pts/0 00:00:01 root /usr/sbin/sshd\n"
	require.NotPanics(t, func() {
		procs, err := processes.ParseAixPsResult(strings.NewReader(input))
		require.NoError(t, err)
		require.Empty(t, procs)
	})
}

func TestParseFindSocketLine(t *testing.T) {
	fi, err := os.Open("./testdata/find_printf_nginx_container.txt")
	require.NoError(t, err)
	defer fi.Close()

	scanner := bufio.NewScanner(fi)

	// "3 socket:[41866685] /proc/1/fd"
	scanner.Scan()
	pid, inode, err := processes.ParseFindSocketLine(scanner.Text())
	require.NoError(t, err)
	require.Equal(t, int64(1), pid)
	require.Equal(t, int64(41866685), inode)

	// "11 socket:[18472] /proc/1/fd"
	scanner.Scan()
	pid, inode, err = processes.ParseFindSocketLine(scanner.Text())
	require.NoError(t, err)
	require.Equal(t, int64(1), pid)
	require.Equal(t, int64(18472), inode)

	// "6 socket:[41866700] /proc/29/fd"
	scanner.Scan()
	pid, inode, err = processes.ParseFindSocketLine(scanner.Text())
	require.NoError(t, err)
	require.Equal(t, int64(29), pid)
	require.Equal(t, int64(41866700), inode)

	// "7 socket:[41866701] /proc/29/fd"
	scanner.Scan()
	pid, inode, err = processes.ParseFindSocketLine(scanner.Text())
	require.NoError(t, err)
	require.Equal(t, int64(29), pid)
	require.Equal(t, int64(41866701), inode)

	// non-matching lines should return 0,0
	pid, inode, err = processes.ParseFindSocketLine("some random garbage")
	require.NoError(t, err)
	require.Equal(t, int64(0), pid)
	require.Equal(t, int64(0), inode)

	pid, inode, err = processes.ParseFindSocketLine("")
	require.NoError(t, err)
	require.Equal(t, int64(0), pid)
	require.Equal(t, int64(0), inode)
}

func TestParseLinuxFind(t *testing.T) {
	fi, err := os.Open("./testdata/find_nginx_container.txt")
	require.NoError(t, err)
	defer fi.Close()

	scanner := bufio.NewScanner(fi)
	scanner.Scan()
	line := scanner.Text()
	pid, inode, err := processes.ParseLinuxFindLine(line)
	require.NoError(t, err)
	require.Equal(t, int64(0), pid)
	require.Equal(t, int64(0), inode)

	scanner.Scan()
	line = scanner.Text()
	pid, inode, err = processes.ParseLinuxFindLine(line)
	require.NoError(t, err)
	require.Equal(t, int64(0), pid)
	require.Equal(t, int64(0), inode)

	scanner.Scan()
	line = scanner.Text()
	pid, inode, err = processes.ParseLinuxFindLine(line)
	require.NoError(t, err)
	require.Equal(t, int64(1), pid)
	require.Equal(t, int64(41866685), inode)

	scanner.Scan()
	line = scanner.Text()
	pid, inode, err = processes.ParseLinuxFindLine(line)
	require.NoError(t, err)
	require.Equal(t, int64(0), pid)
	require.Equal(t, int64(0), inode)

	scanner.Scan()
	line = scanner.Text()
	pid, inode, err = processes.ParseLinuxFindLine(line)
	require.NoError(t, err)
	require.Equal(t, int64(0), pid)
	require.Equal(t, int64(0), inode)

	scanner.Scan()
	line = scanner.Text()
	pid, inode, err = processes.ParseLinuxFindLine(line)
	require.NoError(t, err)
	require.Equal(t, int64(1), pid)
	require.Equal(t, int64(18472), inode)
}

// testdata/aix73.toml is ps with the state column on AIX 7.3 TL4 SP2, cut to
// its first 28 processes, plus a zombie, whose other columns AIX leaves blank.
func TestAixProcessManagerState(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "aix", Family: []string{"unix", "os"}},
	}, mock.WithPath("./testdata/aix73.toml"))
	require.NoError(t, err)

	pm, err := processes.ResolveManager(conn)
	require.NoError(t, err)
	procs, err := pm.List()
	require.NoError(t, err)
	assert.Len(t, procs, 28)

	var init *processes.OSProcess
	for _, p := range procs {
		if p.Pid == 1 {
			init = p
		}
	}
	require.NotNil(t, init)
	assert.Equal(t, "/etc/init", init.Command)
	assert.Equal(t, "A (active)", init.State)
}

func TestAixPSProcessParserKeepsCommandsNamedDefunct(t *testing.T) {
	input := "     PID  %CPU  %MEM   VSZ     TT        TIME   UID S COMMAND\n" +
		" 1638710                             00:00:00       Z <defunct>\n" +
		" 4242424   0.0   0.0   512      -    00:00:00     0 A /usr/local/bin/cleanup_defunct_users.sh\n"
	procs, err := processes.ParseAixPsResult(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, procs, 1)
	assert.Equal(t, "/usr/local/bin/cleanup_defunct_users.sh", procs[0].Command)
}
