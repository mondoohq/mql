// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"fmt"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// al2027NodeTarball is `LC_ALL=C ls -ldn` on Amazon Linux 2027 with Node
// unpacked from the official tarball into /usr/local, which left uid 1000
// owning /usr/local/bin and /usr/local/lib. sudo's secure_path there is
// al2027SecurePath. /opt/tools holds a root-owned script installed by root.
const al2027NodeTarball = `dr-xr-xr-x. 19    0    0       248 Sep 29 19:51 /
lrwxrwxrwx.  1    0    0         7 Jul 14 00:00 /bin -> usr/bin
lrwxrwxrwx.  1    0    0         8 Jul 14 00:00 /sbin -> usr/sbin
drwxr-xr-x. 11    0    0       144 Sep 29 19:50 /usr
dr-xr-xr-x.  2    0    0     32768 Oct  3 08:19 /usr/bin
-rwxr-xr-x.  1    0    0     49640 Jul 31 00:00 /usr/bin/env
lrwxrwxrwx.  1    0    0         3 Oct  3 16:30 /usr/bin/genv -> env
lrwxrwxrwx.  1    0    0         4 Jul 23  2025 /usr/bin/sh -> bash
-rwxr-xr-x.  1    0    0   1446024 Jul 23  2025 /usr/bin/bash
drwxr-xr-x. 11    0    0       183 Oct  3 08:25 /usr/local
drwxr-xr-x.  2 1000 1000       147 Oct  3 16:24 /usr/local/bin
-rwxr-xr-x.  1 1000 1000 123183528 Sep 24  2025 /usr/local/bin/node
lrwxrwxrwx.  1    0    0         3 Sep 29 19:50 /usr/local/sbin -> bin
lrwxrwxrwx.  1    0    0         3 Sep 29 19:50 /usr/sbin -> bin
drwxr-xr-x. 18    0    0     16384 Oct  3 08:06 /var
drwxr-xr-x. 26    0    0     16384 Oct  3 08:26 /var/lib
drwxr-xr-x.  3    0    0        17 Oct  3 16:30 /opt
drwxr-xr-x.  2    0    0        40 Oct  3 16:30 /opt/tools
-rwxr-xr-x.  1    0    0        60 Oct  3 16:30 /opt/tools/envtool
-rwxr-xr-x.  1    0    0        60 Oct  3 16:30 /opt/tools/directtool
-rwxr-xr-x.  1    0    0        60 Oct  3 16:30 /opt/tools/shtool
-rwxr-xr-x.  1    0    0        60 Oct  3 16:30 /opt/tools/elftool
`

const al2027SecurePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/var/lib/snapd/snap/bin"

// rocky9Node is the same on Rocky 9 with Node from the distro's nodejs
// package; /usr/local/bin is root's and secure_path leaves it out.
const rocky9Node = `drwxr-xr-x. 19 0 0   270 Jun 24 17:04 /
lrwxrwxrwx.  1 0 0     7 Nov  3  2024 /bin -> usr/bin
lrwxrwxrwx.  1 0 0     8 Nov  3  2024 /sbin -> usr/sbin
drwxr-xr-x. 12 0 0   144 Jun 24 16:59 /usr
dr-xr-xr-x.  2 0 0 24576 Oct  3 12:32 /usr/bin
-rwxr-xr-x.  1 0 0 45088 Jan 17  2026 /usr/bin/env
lrwxrwxrwx.  1 0 0     7 Aug 31 15:21 /usr/bin/node -> node-22
-rwxr-xr-x.  1 0 0 27768 Aug 31 15:22 /usr/bin/node-22
drwxr-xr-x. 12 0 0   131 Jun 24 16:59 /usr/local
drwxr-xr-x.  2 0 0    97 Oct  3 16:24 /usr/local/bin
dr-xr-xr-x.  2 0 0 12288 Oct  3 12:32 /usr/sbin
drwxr-xr-x.  3 0 0    17 Oct  3 16:30 /opt
drwxr-xr-x.  2 0 0    40 Oct  3 16:30 /opt/tools
-rwxr-xr-x.  1 0 0    60 Oct  3 16:30 /opt/tools/envtool
`

const rocky9SecurePath = "/sbin:/bin:/usr/sbin:/usr/bin"

const elf = "\x7fELF\x02\x01\x01\x00"

// fakeProbe builds an execProbe over captured ls output, file heads and PATH.
func fakeProbe(ls string, heads map[string]string, pathEnv string) execProbe {
	lstat, _ := fakeLstat(ls)
	return execProbe{
		uid:   0,
		lstat: lstat,
		head: func(p string) ([]byte, error) {
			h, ok := heads[p]
			if !ok {
				return nil, fmt.Errorf("cannot read %s: %w", p, fs.ErrPermission)
			}
			return []byte(h), nil
		},
		path: func() (string, bool) { return pathEnv, pathEnv != "" },
	}
}

func al2027Heads() map[string]string {
	return map[string]string{
		"/usr/bin/env":          elf,
		"/usr/bin/bash":         elf,
		"/usr/local/bin/node":   elf,
		"/opt/tools/envtool":    "#!/usr/bin/env node\nconsole.log(1)\n",
		"/opt/tools/directtool": "#!/usr/local/bin/node\nconsole.log(1)\n",
		"/opt/tools/shtool":     "#!/bin/sh\necho 1\n",
		"/opt/tools/elftool":    elf,
	}
}

// A root-owned script whose `#!/usr/bin/env node` finds node in a directory
// uid 1000 owns would run uid 1000's node as root.
func TestTrustedExecutableEnvInterpreter(t *testing.T) {
	x := fakeProbe(al2027NodeTarball, al2027Heads(), al2027SecurePath)
	target, reason := trustedExecutable("/opt/tools/envtool", x, 0)
	assert.Equal(t, "/opt/tools/envtool", target)
	assert.Equal(t, "interpreter node: PATH entry /usr/local/sbin: /usr/local/bin is owned by uid 1000 with mode drwxr-xr-x", reason)

	// the account that owns /usr/local may run its own node
	x.uid = 1000
	_, reason = trustedExecutable("/opt/tools/envtool", x, 0)
	assert.Empty(t, reason)
}

// The same when the script names the interpreter directly.
func TestTrustedExecutableDirectInterpreter(t *testing.T) {
	x := fakeProbe(al2027NodeTarball, al2027Heads(), al2027SecurePath)
	_, reason := trustedExecutable("/opt/tools/directtool", x, 0)
	assert.Equal(t, "interpreter /usr/local/bin/node: /usr/local/bin is owned by uid 1000 with mode drwxr-xr-x", reason)
}

// Interpreters and binaries in root's directories run.
func TestTrustedExecutableTrustedInterpreters(t *testing.T) {
	x := fakeProbe(al2027NodeTarball, al2027Heads(), al2027SecurePath)
	_, reason := trustedExecutable("/opt/tools/shtool", x, 0)
	assert.Empty(t, reason, "/bin/sh resolves through /bin -> usr/bin and sh -> bash, all root's")
	_, reason = trustedExecutable("/opt/tools/elftool", x, 0)
	assert.Empty(t, reason)

	// Rocky 9: env finds node through /bin -> usr/bin, root's all the way
	r := fakeProbe(rocky9Node, map[string]string{
		"/usr/bin/env":       elf,
		"/usr/bin/node-22":   elf,
		"/opt/tools/envtool": "#!/usr/bin/env node\n",
	}, rocky9SecurePath)
	_, reason = trustedExecutable("/opt/tools/envtool", r, 0)
	assert.Empty(t, reason)
}

// env walks PATH in order: a directory another account owns ahead of the one
// holding the interpreter lets that account put its own interpreter first.
func TestTrustedExecutableEarlierPathEntry(t *testing.T) {
	ls := rocky9Node + "drwxr-xr-x.  2 1000 1000 97 Oct  3 16:24 /opt/userbin\n"
	r := fakeProbe(ls, map[string]string{
		"/usr/bin/env":       elf,
		"/usr/bin/node-22":   elf,
		"/opt/tools/envtool": "#!/usr/bin/env node\n",
	}, "/opt/userbin:"+rocky9SecurePath)
	_, reason := trustedExecutable("/opt/tools/envtool", r, 0)
	assert.Equal(t, "interpreter node: PATH entry /opt/userbin: /opt/userbin is owned by uid 1000 with mode drwxr-xr-x", reason)

	// a PATH entry that does not exist, under directories root owns, is
	// skipped; one that is relative is not
	r.path = func() (string, bool) { return "/var/lib/snapd/snap/bin:" + rocky9SecurePath, true }
	r.lstat, _ = fakeLstat(rocky9Node + "drwxr-xr-x. 18 0 0 16384 Oct  3 08:06 /var\ndrwxr-xr-x. 26 0 0 16384 Oct  3 08:26 /var/lib\n")
	_, reason = trustedExecutable("/opt/tools/envtool", r, 0)
	assert.Empty(t, reason)
	r.path = func() (string, bool) { return "bin:" + rocky9SecurePath, true }
	_, reason = trustedExecutable("/opt/tools/envtool", r, 0)
	assert.Equal(t, "interpreter node: PATH entry bin is not absolute", reason)

	// no PATH to resolve against
	r.path = func() (string, bool) { return "", false }
	_, reason = trustedExecutable("/opt/tools/envtool", r, 0)
	assert.Equal(t, "interpreter node: the PATH commands run with is unknown", reason)
}

func TestTrustedExecutableEnvArguments(t *testing.T) {
	heads := al2027Heads()
	run := func(shebang string) string {
		heads["/opt/tools/elftool"] = shebang
		x := fakeProbe(al2027NodeTarball, heads, "/usr/bin")
		_, reason := trustedExecutable("/opt/tools/elftool", x, 0)
		return reason
	}
	assert.Empty(t, run("#!/usr/bin/env bash\n"))
	assert.Empty(t, run("#!/usr/bin/env -S bash -e\n"))
	assert.Empty(t, run("#! /usr/bin/env LANG=C bash\n"))
	assert.Equal(t, "interpreter node: node is not found on PATH", run("#!/usr/bin/env node\n"))
	assert.Equal(t, "env changes PATH", run("#!/usr/bin/env PATH=/usr/local/bin node\n"))
	assert.Equal(t, "env option -i is not understood", run("#!/usr/bin/env -i bash\n"))
	assert.Equal(t, "env names no program", run("#!/usr/bin/env\n"))
	assert.Equal(t, "interpreter /usr/local/bin/node: /usr/local/bin is owned by uid 1000 with mode drwxr-xr-x",
		run("#!/usr/bin/env /usr/local/bin/node\n"))
	assert.Equal(t, "interpreter bin/node is not absolute", run("#!/usr/bin/env bin/node\n"))
	assert.Equal(t, "interpreter node is not absolute", run("#!node\n"))
	// a link to env under another name is env too
	assert.Equal(t, "interpreter node: node is not found on PATH", run("#!/usr/bin/genv node\n"))
	assert.Equal(t, "the file names no interpreter", run("#!\n"))
}

// A file that cannot be read cannot be told apart from a script.
func TestTrustedExecutableUnreadable(t *testing.T) {
	heads := al2027Heads()
	delete(heads, "/opt/tools/elftool")
	x := fakeProbe(al2027NodeTarball, heads, al2027SecurePath)
	_, reason := trustedExecutable("/opt/tools/elftool", x, 0)
	assert.Equal(t, "cannot read /opt/tools/elftool: permission denied", reason)

	// RHEL's sudo is mode 4111: an unprivileged scan may run it without
	// reading it
	x.uid = 1000
	_, reason = trustedExecutable("/opt/tools/elftool", x, 0)
	assert.Empty(t, reason)
}

// The kernel follows at most four levels of interpreter scripts.
func TestTrustedExecutableInterpreterDepth(t *testing.T) {
	ls := al2027NodeTarball
	heads := al2027Heads()
	for _, n := range []string{"s1", "s2", "s3", "s4", "s5"} {
		ls += "-rwxr-xr-x.  1    0    0        60 Oct  3 16:30 /opt/tools/" + n + "\n"
	}
	heads["/opt/tools/s1"] = "#!/opt/tools/s2\n"
	heads["/opt/tools/s2"] = "#!/opt/tools/s3\n"
	heads["/opt/tools/s3"] = "#!/opt/tools/s4\n"
	heads["/opt/tools/s4"] = "#!/opt/tools/s5\n"
	heads["/opt/tools/s5"] = "#!/bin/sh\n"
	x := fakeProbe(ls, heads, al2027SecurePath)
	_, reason := trustedExecutable("/opt/tools/s2", x, 0)
	assert.Empty(t, reason)
	_, reason = trustedExecutable("/opt/tools/s1", x, 0)
	assert.Contains(t, reason, "interpreters nest deeper than the kernel follows")
}

func TestParseShebang(t *testing.T) {
	interp, arg, ok := parseShebang([]byte("#!/usr/bin/env node\n// rest"))
	require.True(t, ok)
	assert.Equal(t, "/usr/bin/env", interp)
	assert.Equal(t, "node", arg)

	// the kernel splits off the interpreter at the first blank and passes the
	// rest of the line as one argument
	interp, arg, ok = parseShebang([]byte("#! \t/usr/bin/env -S node --no-warnings \t\n"))
	require.True(t, ok)
	assert.Equal(t, "/usr/bin/env", interp)
	assert.Equal(t, "-S node --no-warnings", arg)

	interp, _, ok = parseShebang([]byte("#!/bin/sh"))
	require.True(t, ok)
	assert.Equal(t, "/bin/sh", interp)

	_, _, ok = parseShebang([]byte(elf))
	assert.False(t, ok)
	_, _, ok = parseShebang(nil)
	assert.False(t, ok)
}
