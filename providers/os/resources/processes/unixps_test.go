// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes_test

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"

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

// ps prints the whole command line of every process. Any user can start a
// process whose arguments are longer than 64 KiB; the processes listed
// after it must still be reported.
func TestParseLinuxPsResultKeepsProcessesAfterLongCommand(t *testing.T) {
	out := "  PID %CPU %MEM    VSZ   RSS TT       STAT STIME     TIME   UID COMMAND\n" +
		"    1 0.0  0.1  12124  3232  ?        Ss   07:48   00:00:00     0 /sbin/init\n" +
		" 4100 0.0  0.0   5584  1024  ?        S    07:50   00:00:00  1000 sleep " + strings.Repeat("a", 70000) + "\n" +
		" 4101 0.0  0.0   5584  1024  ?        S    07:50   00:00:00  1000 /tmp/miner --pool example\n"

	m, err := processes.ParseLinuxPsResult(strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, m, 3)
	assert.Equal(t, int64(4101), m[2].Pid)
	assert.Equal(t, "/tmp/miner --pool example", m[2].Command)
}

func TestParseUnixPsResultKeepsProcessesAfterLongCommand(t *testing.T) {
	out := "  PID  %CPU %MEM   VSZ  RSS TTY   STAT     TIME  UID COMMAND\n" +
		"    1   0.0  0.2 10056 1052 -     ILs   0:00.01    0 /sbin/init --\n" +
		"  900   0.0  0.2 10056 1052 -     S     0:00.01 1001 sleep " + strings.Repeat("a", 70000) + "\n" +
		"  901   0.0  0.2 10056 1052 -     S     0:00.01 1001 /tmp/miner\n"

	m, err := processes.ParseUnixPsResult(strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, m, 3)
	assert.Equal(t, int64(901), m[2].Pid)
}

func TestParseAixPsResultKeepsProcessesAfterLongCommand(t *testing.T) {
	out := "     PID  %CPU  %MEM   VSZ     TT        TIME UID COMMAND\n" +
		"       1   0.0   0.0   792      -    00:00:00   0 /etc/init\n" +
		"    9000   0.0   0.0   792      -    00:00:00 201 sleep " + strings.Repeat("a", 70000) + "\n" +
		"    9001   0.0   0.0   792      -    00:00:00 201 /tmp/miner\n"

	m, err := processes.ParseAixPsResult(strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, m, 3)
	assert.Equal(t, int64(9001), m[2].Pid)
}

// A ps output that cannot be read to the end must fail the list rather than
// report the processes read so far as all of them.
func TestParsePsResultReturnsReadError(t *testing.T) {
	head := "  PID %CPU %MEM    VSZ   RSS TT       STAT STIME     TIME   UID COMMAND\n" +
		"    1 0.0  0.1  12124  3232  ?        Ss   07:48   00:00:00     0 /sbin/init\n"
	_, err := processes.ParseLinuxPsResult(io.MultiReader(strings.NewReader(head), iotest.ErrReader(errors.New("boom"))))
	assert.Error(t, err)
	_, err = processes.ParseUnixPsResult(io.MultiReader(strings.NewReader(head), iotest.ErrReader(errors.New("boom"))))
	assert.Error(t, err)
	_, err = processes.ParseAixPsResult(io.MultiReader(strings.NewReader(head), iotest.ErrReader(errors.New("boom"))))
	assert.Error(t, err)
}
