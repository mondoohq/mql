// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/packages"
)

// rhel7ExecConn mocks RHEL 7.9 with Node unpacked from the official tarball as
// root (tar kept the archive's uid 1000 on /usr/local/lib), Claude Code from
// `npm install -g`, and Ollama in /usr/bin. Commands run as uid.
func rhel7ExecConn(t *testing.T, id uint32, uid string) *mock.Connection {
	t.Helper()
	const lsPrefix = `dr-xr-xr-x. 17    0    0       224 Oct  2 23:58 /
drwxr-xr-x. 13    0    0       155 Sep 30  2024 /usr
drwxr-xr-x. 12    0    0       183 Oct  3 01:00 /usr/local
drwxr-xr-x.  2    0    0       133 Oct  3 01:00 /usr/local/bin
`
	cmds := map[string]*mock.Command{
		"id -u": {Stdout: uid + "\n"},
		// sudo's secure_path on RHEL leaves out /usr/local/bin
		"command -v 'claude'":  {ExitStatus: 1},
		"command -v 'ollama'":  {Stdout: "/usr/bin/ollama\n"},
		"command -v 'kubelet'": {ExitStatus: 1},
		"LC_ALL=C ls -ldn -- '/' '/usr' '/usr/local' '/usr/local/bin' '/usr/local/bin/claude'": {Stdout: lsPrefix +
			"lrwxrwxrwx.  1    0    0        60 Oct  3 01:00 /usr/local/bin/claude -> ../lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe\n"},
		"LC_ALL=C ls -ldn -- '/' '/usr' '/usr/local' '/usr/local/lib' '/usr/local/lib/node_modules' '/usr/local/lib/node_modules/@anthropic-ai' '/usr/local/lib/node_modules/@anthropic-ai/claude-code' '/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin' '/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe'": {Stdout: `dr-xr-xr-x. 17    0    0       224 Oct  2 23:58 /
drwxr-xr-x. 13    0    0       155 Sep 30  2024 /usr
drwxr-xr-x. 12    0    0       183 Oct  3 01:00 /usr/local
drwxr-xr-x.  4 1000 1000        40 Oct  3 01:01 /usr/local/lib
drwxr-xr-x.  8 1000 1000       102 Oct  3 02:05 /usr/local/lib/node_modules
drwxr-xr-x.  3    0    0        25 Oct  3 01:00 /usr/local/lib/node_modules/@anthropic-ai
drwxr-xr-x.  4    0    0       156 Oct  3 01:00 /usr/local/lib/node_modules/@anthropic-ai/claude-code
drwxr-xr-x.  2    0    0        24 Oct  3 01:00 /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin
-rwxr-xr-x.  2    0    0 245517112 Oct  3 01:00 /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
`},
		"LC_ALL=C ls -ldn -- '/' '/usr' '/usr/bin' '/usr/bin/ollama'": {Stdout: `dr-xr-xr-x. 17    0    0       224 Oct  2 23:58 /
drwxr-xr-x. 13    0    0       155 Sep 30  2024 /usr
dr-xr-xr-x.  2    0    0     40960 Oct  2 16:55 /usr/bin
-rwxr-xr-x.  1    0    0  28627920 Oct  2 16:55 /usr/bin/ollama
`},
		// a root-owned script run through `#!/usr/bin/env claude`
		"printenv PATH": {Stdout: "/usr/local/bin:/usr/bin\n"},
		"LC_ALL=C ls -ldn -- '/' '/usr' '/usr/bin' '/usr/bin/envtool'": {Stdout: `dr-xr-xr-x. 17    0    0       224 Oct  2 23:58 /
drwxr-xr-x. 13    0    0       155 Sep 30  2024 /usr
dr-xr-xr-x.  2    0    0     40960 Oct  2 16:55 /usr/bin
-rwxr-xr-x.  1    0    0        40 Oct  2 16:55 /usr/bin/envtool
`},
		"LC_ALL=C ls -ldn -- '/' '/usr' '/usr/bin' '/usr/bin/env'": {Stdout: `dr-xr-xr-x. 17    0    0       224 Oct  2 23:58 /
drwxr-xr-x. 13    0    0       155 Sep 30  2024 /usr
dr-xr-xr-x.  2    0    0     40960 Oct  2 16:55 /usr/bin
-rwxr-xr-x.  1    0    0     28992 Oct  2 16:55 /usr/bin/env
`},
		"LC_ALL=C ls -ldn -- '/' '/usr' '/usr/local' '/usr/local/bin'": {Stdout: lsPrefix},
		"LC_ALL=C ls -ldn -- '/usr/local/bin/claude'":                  {Stdout: "lrwxrwxrwx.  1    0    0        60 Oct  3 01:00 /usr/local/bin/claude -> ../lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe\n"},
		// a process that named itself /tmp/k/kubelet
		"LC_ALL=C ls -ldn -- '/' '/tmp' '/tmp/k' '/tmp/k/kubelet'": {Stdout: `dr-xr-xr-x. 17    0    0       224 Oct  2 23:58 /
drwxrwxrwt. 10    0    0      4096 Oct  3 02:05 /tmp
drwxr-xr-x.  2 1000 1000        20 Oct  3 02:05 /tmp/k
-rwxr-xr-x.  1 1000 1000        40 Oct  3 02:05 /tmp/k/kubelet
`},
	}
	conn, err := mock.New(id, &inventory.Asset{
		Platform: &inventory.Platform{Name: "redhat", Version: "7.9", Family: []string{"redhat", "linux", "unix", "os"}},
	}, mock.WithData(&mock.TomlData{
		Commands: cmds,
		Files: map[string]*mock.MockFileData{
			"/usr/local/bin/claude": {Path: "/usr/local/bin/claude", Content: "ELF", StatData: mock.FileInfo{Mode: 0o755}},
			"/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe": {Content: "\x7fELF"},
			"/usr/bin/ollama":  {Content: "\x7fELF"},
			"/usr/bin/env":     {Content: "\x7fELF"},
			"/usr/bin/envtool": {Content: "#!/usr/bin/env claude\n"},
		},
	}))
	require.NoError(t, err)
	return conn
}

func TestRunnableBinary(t *testing.T) {
	root := rhel7ExecConn(t, 9100, "0")
	// uid 1000 owns /usr/local/lib/node_modules and could swap claude for
	// anything: a root scan does not run it
	assert.Empty(t, runnableBinary(root, "/usr/local/bin/claude"))
	// a root-owned binary in root-owned directories runs
	assert.Equal(t, "/usr/bin/ollama", runnableBinary(root, "/usr/bin/ollama"))
	// a root-owned script whose interpreter env finds in a tree uid 1000 owns
	assert.Empty(t, runnableBinary(root, "/usr/bin/envtool"))
	// a process can name itself after a path it controls
	assert.Empty(t, runnableBinary(root, "/tmp/k/kubelet"))
	// a bare name is left to the PATH, like any other command
	assert.Equal(t, "kubelet", runnableBinary(root, "kubelet"))

	// the account that owns the tree may run what it owns
	owner := rhel7ExecConn(t, 9101, "1000")
	assert.Equal(t, "/usr/local/bin/claude", runnableBinary(owner, "/usr/local/bin/claude"))
	assert.Equal(t, "/usr/bin/envtool", runnableBinary(owner, "/usr/bin/envtool"))
	// another account may not
	other := rhel7ExecConn(t, 9102, "1500")
	assert.Empty(t, runnableBinary(other, "/usr/local/bin/claude"))

	// the tool version lookup finds claude where sudo's PATH does not reach,
	// and still does not run it as root
	bin, found := packages.LocateBinary(root, "claude")
	require.True(t, found)
	assert.False(t, bin.Trusted)
	assert.Equal(t, "/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe", bin.Target)
	bin, found = packages.LocateBinary(root, "ollama")
	require.True(t, found)
	assert.True(t, bin.Trusted)
}
