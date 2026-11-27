// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func TestParseSocketInode(t *testing.T) {
	tests := []struct {
		link      string
		wantInode int64
		wantErr   bool
	}{
		{"socket:[41866700]", 41866700, false},
		{"socket:[0]", 0, false},
		{"socket:[999999999]", 999999999, false},
		{"pipe:[12345]", -1, false},
		{"/dev/null", -1, false},
		{"", -1, false},
		{"socket:[]", 0, true},
		{"socket:[notanumber]", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.link, func(t *testing.T) {
			inode, err := ParseSocketInode(tt.link)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantInode, inode)
			}
		})
	}
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return string(data)
}

// procs reduces a process list to pid -> "executable|command|state".
func procs(list []*OSProcess) map[int64]string {
	res := map[int64]string{}
	for _, p := range list {
		res[p.Pid] = p.Executable + "|" + p.Command + "|" + p.State
	}
	return res
}

// The fixtures are procDumpCommand(), run with docker exec in each
// container (os provider not involved). The expected values are what
// processes.list returned for the same containers, read file by file through
// the released code path.
func TestParseProcDumpMeasured(t *testing.T) {
	tests := []struct {
		fixture string
		want    map[int64]string
	}{
		{
			// Measured: php:8.3-apache, Debian 13.7, arm64, Docker Desktop 29.9.3, 2026-11-27
			fixture: "procdump-php83-apache-debian13.bin",
			want: map[int64]string{
				1:  "apache2|apache2 -DFOREGROUND|S (sleeping)",
				17: "apache2|apache2 -DFOREGROUND|S (sleeping)",
				18: "apache2|apache2 -DFOREGROUND|S (sleeping)",
				19: "apache2|apache2 -DFOREGROUND|S (sleeping)",
				20: "apache2|apache2 -DFOREGROUND|S (sleeping)",
				21: "apache2|apache2 -DFOREGROUND|S (sleeping)",
			},
		},
		{
			// Measured: postgres:16, Debian 13.5, arm64, 2026-11-27. The
			// workers rewrite their titles, with a trailing empty argument.
			fixture: "procdump-postgres16-debian13.bin",
			want: map[int64]string{
				1:  "postgres|postgres|S (sleeping)",
				60: "postgres|postgres: checkpointer|S (sleeping)",
				61: "postgres|postgres: background writer|S (sleeping)",
				63: "postgres|postgres: walwriter|S (sleeping)",
				64: "postgres|postgres: autovacuum launcher|S (sleeping)",
				65: "postgres|postgres: logical replication launcher|S (sleeping)",
			},
		},
		{
			// Measured: alpine:3.20 (BusyBox sh, sed, base64), arm64, 2026-11-27
			fixture: "procdump-alpine320.bin",
			want:    map[int64]string{1: "sleep|sleep infinity|S (sleeping)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			list, err := parseProcDump(strings.NewReader(readFixture(t, tt.fixture)))
			require.NoError(t, err)
			assert.Equal(t, tt.want, procs(list))
		})
	}
}

// procDumpEntry builds one process of procDumpCommand's output.
func procDumpEntry(pid, cmdline, comm, status string) string {
	return "P" + pid + "\x00" + base64.StdEncoding.EncodeToString([]byte(cmdline)) + "\x00" + comm + "\x00" + status + "\x00"
}

// Synthetic: shapes no measured container showed.
func TestParseProcDumpSynthetic(t *testing.T) {
	t.Run("no processes", func(t *testing.T) {
		list, err := parseProcDump(strings.NewReader(""))
		require.NoError(t, err)
		assert.Empty(t, list)
	})

	t.Run("cmdline edge cases", func(t *testing.T) {
		dump := procDumpEntry("7", "/usr/local/bin/kube-controller-manager\x00--profiling=false\x00", "kube-controller\n", "Name:\tkube-controller\nState:\tS (sleeping)\n") +
			// empty arguments in the middle of cmdline
			procDumpEntry("8", "/bin/app\x00\x00--flag\x00", "app\n", "Name:\tapp\nState:\tR (running)\n") +
			// a zombie has no cmdline, so its command is comm
			procDumpEntry("9", "", "defunct-child\n", "Name:\tdefunct-child\nState:\tZ (zombie)\n") +
			// exited while it was read: no status
			procDumpEntry("10", "", "", "")
		list, err := parseProcDump(strings.NewReader(dump))
		require.NoError(t, err)
		assert.Equal(t, map[int64]string{
			7: "kube-controller-manager|/usr/local/bin/kube-controller-manager --profiling=false|S (sleeping)",
			8: "app|/bin/app --flag|R (running)",
			9: "defunct-child|defunct-child|Z (zombie)",
		}, procs(list))
	})

	for name, dump := range map[string]string{
		"cut short":             procDumpEntry("1", "init\x00", "init\n", "Name:\tinit\n")[:20],
		"not the dump":          "sh: base64: not found\n",
		"cmdline not base64":    "P1\x00not base64!\x00init\n\x00Name:\tinit\n\x00",
		"entry without its pid": "Px\x00\x00\x00Name:\tinit\n\x00",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseProcDump(strings.NewReader(dump))
			assert.Error(t, err)
		})
	}
}

func TestParseSocketInodesDump(t *testing.T) {
	// Measured: socketInodesDumpCommand in php:8.3-apache (Debian 13.7, arm64),
	// run with docker exec, 2026-11-27. Only the root master process holds
	// the listening socket; ports.listening reported port 80 for pid 1.
	res, err := parseSocketInodesDump(strings.NewReader(readFixture(t, "sockdump-php83-apache-debian13.txt")))
	require.NoError(t, err)
	assert.Equal(t, []int64{1424795}, res[1].Data)
	for _, pid := range []int64{17, 18, 19, 20, 21} {
		v, ok := res[pid]
		assert.True(t, ok, "every listed process has an entry")
		assert.Empty(t, v.Data)
	}
	assert.Len(t, res, 6)

	// Measured: postgres:16 (Debian 13.5), 2026-11-27. The processes run as
	// postgres and docker exec as root without CAP_SYS_PTRACE, so ls lists
	// the descriptors without their targets: no sockets, not an error.
	res, err = parseSocketInodesDump(strings.NewReader(readFixture(t, "sockdump-postgres16-debian13.txt")))
	require.NoError(t, err)
	assert.Len(t, res, 6)
	for pid, v := range res {
		assert.Empty(t, v.Data, "pid %d", pid)
	}

	// Synthetic: lines no container showed.
	res, err = parseSocketInodesDump(strings.NewReader(strings.Join([]string{
		"lrwx------ 1 root root 64 Nov 27 14:20 3 -> socket:[1]", // before any process
		"P42",
		"total 0",
		"lrwx------ 1 root root 64 Nov 27 14:20 3 -> socket:[100]",
		"lrwx------ 1 root root 64 Nov 27 14:20 4 -> socket:[101]",
		"l-wx------ 1 root root 64 Nov 27 14:20 5 -> pipe:[102]",
		"lrwx------ 1 root root 64 Nov 27 14:20 6 -> socket:[bad]",
		"Pnot-a-pid",
		"P43",
	}, "\n")))
	require.NoError(t, err)
	assert.Equal(t, map[int64]plugin.TValue[[]int64]{
		42: {Data: []int64{100, 101}, State: plugin.StateIsSet},
		43: {Data: []int64{}, State: plugin.StateIsSet},
	}, res)
}

// cmdProcConn is a connection that is not local and runs commands, as a
// running docker container is. It answers the dump commands from fixed
// output and counts every command it runs.
type cmdProcConn struct {
	fakeProcConn
	outputs  map[string]string
	exit     int
	commands []string
}

func (c *cmdProcConn) Type() shared.ConnectionType { return shared.Type_DockerContainer }
func (c *cmdProcConn) Capabilities() shared.Capabilities {
	return shared.Capability_File | shared.Capability_RunCommand
}

func (c *cmdProcConn) RunCommand(command string) (*shared.Command, error) {
	c.commands = append(c.commands, command)
	out, ok := c.outputs[command]
	exit := c.exit
	if !ok {
		out, exit = "", 127
	}
	return &shared.Command{Command: command, Stdout: bytes.NewBufferString(out), Stderr: &bytes.Buffer{}, ExitStatus: exit}, nil
}

// Over a connection that reads /proc with commands, listing processes takes
// one command and does not touch file descriptors; their sockets take one
// more, when asked. The filesystem holds no /proc at all, so nothing can have
// come from it.
func TestLinuxProcManagerByCommand(t *testing.T) {
	procDump := readFixture(t, "procdump-php83-apache-debian13.bin")
	conn := &cmdProcConn{
		fakeProcConn: fakeProcConn{fs: afero.NewMemMapFs()},
		outputs: map[string]string{
			procDumpCommand():       procDump,
			procDumpCommand(17):     procDumpEntry("17", "apache2\x00-DFOREGROUND\x00", "apache2\n", "Name:\tapache2\nState:\tS (sleeping)\n"),
			procDumpCommand(999):    "",
			socketInodesDumpCommand: readFixture(t, "sockdump-php83-apache-debian13.txt"),
		},
	}
	lpm := &LinuxProcManager{conn: conn}

	list, err := lpm.List()
	require.NoError(t, err)
	assert.Len(t, list, 6)
	assert.Equal(t, []string{procDumpCommand()}, conn.commands, "one command lists every process, and no fd is read")

	conn.commands = nil
	p, err := lpm.Process(17)
	require.NoError(t, err)
	assert.Equal(t, "apache2|apache2 -DFOREGROUND|S (sleeping)", procs([]*OSProcess{p})[17])
	assert.Len(t, conn.commands, 1)

	_, err = lpm.Process(999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")

	conn.commands = nil
	sockets, err := lpm.ListSocketInodesByProcess()
	require.NoError(t, err)
	assert.Equal(t, []int64{1424795}, sockets[1].Data)
	assert.Equal(t, []string{socketInodesDumpCommand}, conn.commands)
}

// Synthetic: a container without base64 (the dump exits 4) is read file by
// file, as before.
func TestLinuxProcManagerByCommandFallsBack(t *testing.T) {
	lpm := newLinuxProcManager(t)
	conn := &cmdProcConn{fakeProcConn: *lpm.conn.(*fakeProcConn), exit: 4, outputs: map[string]string{
		procDumpCommand():   "",
		procDumpCommand(42): "",
	}}
	lpm.conn = conn

	list, err := lpm.List()
	require.NoError(t, err)
	assert.Equal(t, map[int64]string{1: "init|init|S (sleeping)", 42: "bash|bash|S (sleeping)", 1337: "nginx|nginx|S (sleeping)"}, procs(list))

	p, err := lpm.Process(42)
	require.NoError(t, err)
	assert.Equal(t, "bash", p.Command)
}

// readlinkCountingFs counts how many fd links are resolved.
type readlinkCountingFs struct {
	*afero.BasePathFs
	readlinks int
}

func (fs *readlinkCountingFs) ReadlinkIfPossible(name string) (string, error) {
	fs.readlinks++
	return fs.BasePathFs.ReadlinkIfPossible(name)
}

// Synthetic: a local /proc tree with socket and pipe fd links. List reads no
// fd, ListSocketInodesByProcess resolves them all.
func TestLinuxProcManagerSocketsOnlyWhenAsked(t *testing.T) {
	root := t.TempDir()
	for pid, links := range map[string][]string{
		"1":  {"socket:[100]", "pipe:[5]", "socket:[101]"},
		"42": {"/dev/null"},
	} {
		require.NoError(t, os.MkdirAll(root+"/proc/"+pid+"/fd", 0o755))
		require.NoError(t, os.WriteFile(root+"/proc/"+pid+"/cmdline", []byte("p"+pid+"\x00"), 0o644))
		require.NoError(t, os.WriteFile(root+"/proc/"+pid+"/status", []byte("Name:\tp"+pid+"\nState:\tS (sleeping)\n"), 0o644))
		for i, l := range links {
			require.NoError(t, os.Symlink(l, root+"/proc/"+pid+"/fd/"+string(rune('3'+i))))
		}
	}
	fs := &readlinkCountingFs{BasePathFs: afero.NewBasePathFs(afero.NewOsFs(), root).(*afero.BasePathFs)}
	lpm := &LinuxProcManager{conn: &fakeProcConn{fs: fs}}

	list, err := lpm.List()
	require.NoError(t, err)
	assert.Len(t, list, 2)
	assert.Zero(t, fs.readlinks, "listing processes resolves no fd link")

	sockets, err := lpm.ListSocketInodesByProcess()
	require.NoError(t, err)
	assert.ElementsMatch(t, []int64{100, 101}, sockets[1].Data)
	assert.Empty(t, sockets[42].Data)
	assert.Equal(t, 4, fs.readlinks)
}
