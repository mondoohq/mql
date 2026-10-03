// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rhel7NodeTarball is `LC_ALL=C ls -ldn` on RHEL 7.9 with Node installed from
// the official tarball as root and Claude Code from `npm install -g`. tar kept
// the archive's uid 1000 on /usr/local/lib and /usr/local/lib/node_modules.
const rhel7NodeTarball = `dr-xr-xr-x. 17    0    0       224 Oct  2 23:58 /
drwxr-xr-x. 13    0    0       155 Sep 30  2024 /usr
drwxr-xr-x. 12    0    0       183 Oct  3 01:00 /usr/local
drwxr-xr-x.  2    0    0       133 Oct  3 01:00 /usr/local/bin
lrwxrwxrwx.  1    0    0        60 Oct  3 01:00 /usr/local/bin/claude -> ../lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
drwxr-xr-x.  4 1000 1000        40 Oct  3 01:01 /usr/local/lib
drwxr-xr-x.  8 1000 1000       102 Oct  3 02:05 /usr/local/lib/node_modules
drwxr-xr-x.  3    0    0        25 Oct  3 01:00 /usr/local/lib/node_modules/@anthropic-ai
drwxr-xr-x.  4    0    0       156 Oct  3 01:00 /usr/local/lib/node_modules/@anthropic-ai/claude-code
drwxr-xr-x.  2    0    0        24 Oct  3 01:00 /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin
-rwxr-xr-x.  2    0    0 245517112 Oct  3 01:00 /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
lrwxrwxrwx.  1 0 0        7 Sep 30  2024 /bin -> usr/bin
drwxr-xr-x.  2 0 0    40960 Sep 30  2024 /usr/bin
drwxrwxrwt. 10 0 0     4096 Oct  3 02:05 /tmp
-rwxr-xr-x.  1 0 0 28627920 Oct  2 16:55 /usr/bin/ollama
-rwxr-xr-x.  1 0 0 28627920 Oct  2 16:55 /tmp/ollama
`

// fakeLstat answers from captured ls output and counts the calls. A path
// the output does not list is reported on stderr as GNU ls does for a path
// that does not exist.
func fakeLstat(out string) (func([]string) lsResult, *int) {
	calls := 0
	return func(paths []string) lsResult {
		calls++
		all := parseLsLong(out, paths)
		var stdout, stderr strings.Builder
		for _, p := range paths {
			if _, ok := all[p]; !ok {
				stderr.WriteString("ls: cannot access '" + p + "': No such file or directory\n")
				continue
			}
			for _, line := range strings.Split(out, "\n") {
				if strings.HasSuffix(line, " "+p) || strings.Contains(line, " "+p+" -> ") {
					stdout.WriteString(line + "\n")
				}
			}
		}
		return parseLs(stdout.String(), stderr.String(), paths)
	}, &calls
}

func TestParseLsLong(t *testing.T) {
	entries := parseLsLong(rhel7NodeTarball+"ls: cannot access /nonexist: No such file or directory\n", nil)
	require.Contains(t, entries, "/")
	assert.Equal(t, pathEntry{mode: "dr-xr-xr-x", uid: 0, size: 224}, entries["/"])
	assert.Equal(t, int64(245517112), entries["/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"].size)
	assert.Equal(t, int64(1000), entries["/usr/local/lib/node_modules"].uid)
	assert.Equal(t, "../lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe", entries["/usr/local/bin/claude"].link)
	assert.True(t, entries["/usr/local/bin/claude"].isLink())
	assert.True(t, entries["/tmp"].writableByOthers())
	assert.False(t, entries["/usr/local/bin"].writableByOthers())
	assert.NotContains(t, entries, "/nonexist")

	// macOS: ACL/xattr markers after the mode, a group-writable Homebrew bin
	mac := parseLsLong("drwxrwxr-x  563 501  80  18016 Oct  2 08:34 /opt/homebrew/bin\nlrwxr-xr-x@   1 0    0      11 Sep  3 03:34 /tmp -> private/tmp\n", nil)
	assert.Equal(t, int64(501), mac["/opt/homebrew/bin"].uid)
	assert.True(t, mac["/opt/homebrew/bin"].writableByOthers())
	assert.Equal(t, "private/tmp", mac["/tmp"].link)

	// a name holding " -> " is split after the path that was asked for
	odd := parseLsLong("lrwxrwxrwx 1 0 0 7 Apr 22  2024 /opt/a -> b -> /usr/bin/b\n", []string{"/opt", "/opt/a -> b"})
	assert.Equal(t, "/usr/bin/b", odd["/opt/a -> b"].link)
}

func TestTrustedResolution(t *testing.T) {
	// A root scan must not run claude: /usr/local/lib/node_modules belongs to
	// uid 1000, who can swap the package for anything.
	lstat, calls := fakeLstat(rhel7NodeTarball)
	target, reason := trustedResolution("/usr/local/bin/claude", 0, lstat)
	assert.Equal(t, "/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe", target,
		"the resolved path is still reported, to read package.json next to it")
	assert.Equal(t, "/usr/local/lib is owned by uid 1000 with mode drwxr-xr-x", reason)
	assert.Equal(t, 2, *calls, "one lstat per link plus one")

	// uid 1000 itself may run what it owns
	_, reason = trustedResolution("/usr/local/bin/claude", 1000, lstat)
	assert.Empty(t, reason)

	// another non-root account may not
	_, reason = trustedResolution("/usr/local/bin/claude", 1500, lstat)
	assert.NotEmpty(t, reason)

	// a root-owned binary reached through the /bin -> usr/bin link is trusted
	target, reason = trustedResolution("/bin/ollama", 0, lstat)
	assert.Empty(t, reason)
	assert.Equal(t, "/usr/bin/ollama", target)

	// a root-owned file in a world-writable directory is not
	_, reason = trustedResolution("/tmp/ollama", 0, lstat)
	assert.Equal(t, "/tmp is owned by uid 0 with mode drwxrwxrwt", reason)

	// a path that cannot be listed resolves to nothing
	target, reason = trustedResolution("/usr/local/bin/codex", 0, lstat)
	assert.Empty(t, target)
	assert.NotEmpty(t, reason)
}

func TestTrustedResolutionUserOwnedFile(t *testing.T) {
	lstat, _ := fakeLstat(`dr-xr-xr-x. 17    0    0       224 Oct  2 23:58 /
drwxr-xr-x. 13    0    0       155 Sep 30  2024 /usr
drwxr-xr-x. 12    0    0       183 Oct  3 01:00 /usr/local
drwxr-xr-x.  2    0    0       133 Oct  3 01:00 /usr/local/bin
-rwxr-xr-x.  1 1000 1000    28627920 Oct  2 16:55 /usr/local/bin/node
-rwxrwxr-x.  1    0   10    28627920 Oct  2 16:55 /usr/local/bin/ollama
`)
	_, reason := trustedResolution("/usr/local/bin/node", 0, lstat)
	assert.NotEmpty(t, reason, "a file another account owns can be rewritten by it")
	_, reason = trustedResolution("/usr/local/bin/ollama", 0, lstat)
	assert.NotEmpty(t, reason, "a group-writable file can be rewritten by the group")
}

func TestTrustedResolutionLinkLoop(t *testing.T) {
	lstat, _ := fakeLstat(`drwxr-xr-x 22 0 0 4096 Oct  2 23:56 /
drwxr-xr-x 22 0 0 4096 Oct  2 23:56 /opt
lrwxrwxrwx  1 0 0    5 Apr 22  2024 /opt/a -> /opt/b
lrwxrwxrwx  1 0 0    5 Apr 22  2024 /opt/b -> /opt/a
`)
	target, reason := trustedResolution("/opt/a", 0, lstat)
	assert.Empty(t, target)
	assert.Contains(t, reason, "too many symbolic links")
}

// An intermediate link in a directory another account owns lets that account
// point the chain elsewhere, even though the final binary is root's.
func TestTrustedResolutionIntermediateLink(t *testing.T) {
	lstat, _ := fakeLstat(`drwxr-xr-x 22 0 0 4096 Oct  2 23:56 /
drwxr-xr-x 22 0 0 4096 Oct  2 23:56 /usr
drwxr-xr-x 22 0 0 4096 Oct  2 23:56 /usr/bin
lrwxrwxrwx  1 0 0    5 Apr 22  2024 /usr/bin/tool -> /opt/hop/tool
drwxr-xr-x 22 0 0 4096 Oct  2 23:56 /opt
drwxr-xr-x  2 1000 1000 4096 Oct  2 23:56 /opt/hop
lrwxrwxrwx  1 1000 1000    5 Apr 22  2024 /opt/hop/tool -> /usr/libexec/tool
drwxr-xr-x 22 0 0 4096 Oct  2 23:56 /usr/libexec
-rwxr-xr-x  1 0 0 4096 Oct  2 23:56 /usr/libexec/tool
`)
	target, reason := trustedResolution("/usr/bin/tool", 0, lstat)
	assert.Equal(t, "/usr/libexec/tool", target)
	assert.Equal(t, "/opt/hop is owned by uid 1000 with mode drwxr-xr-x", reason)
}

func TestPathComponents(t *testing.T) {
	assert.Empty(t, pathComponents("/"))
	assert.Equal(t, []string{"usr", "bin", "..", "x"}, pathComponents("/usr//bin/./../x/"))
}

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

func rocky9EnvProbe(pathEnv string) execProbe {
	return fakeProbe(rocky9Node, map[string]string{
		"/usr/bin/env":       elf,
		"/usr/bin/node-22":   elf,
		"/opt/tools/envtool": "#!/usr/bin/env node\n",
	}, pathEnv)
}

// A PATH directory that ls could not list is not one that does not exist:
// env would still look there first.
func TestPathLookupUnlistedDirIsNotAbsent(t *testing.T) {
	r := rocky9EnvProbe("/usr/local/bin:/usr/bin")
	_, reason := trustedExecutable("/opt/tools/envtool", r, 0)
	assert.Empty(t, reason, "/usr/local/bin is root's and holds no node, /usr/bin's node is root's")

	inner := r.lstat
	r.lstat = func(p []string) lsResult {
		if p[len(p)-1] == "/usr/local/bin" {
			return lsResult{} // ls failed to run
		}
		return inner(p)
	}
	_, reason = trustedExecutable("/opt/tools/envtool", r, 0)
	assert.Equal(t, "interpreter node: PATH entry /usr/local/bin: / cannot be listed", reason)
}

// The same for the program looked for in a PATH directory.
func TestPathLookupUnlistedCandidateIsNotAbsent(t *testing.T) {
	r := rocky9EnvProbe("/usr/local/bin:/usr/bin")
	inner := r.lstat
	r.lstat = func(p []string) lsResult {
		if len(p) == 1 && p[0] == "/usr/local/bin/node" {
			// ls ran, but printed a line that is not understood
			return parseLs("brw-rw---- 1 0 6 8, 0 Oct  3 16:30 /usr/local/bin/node\n", "", p)
		}
		return inner(p)
	}
	_, reason := trustedExecutable("/opt/tools/envtool", r, 0)
	assert.Equal(t, "interpreter node: PATH entry /usr/local/bin: /usr/local/bin/node cannot be listed", reason)
}

// Only a "No such file" from ls for that very path reads as absent.
func TestParseLsAbsent(t *testing.T) {
	paths := []string{"/", "/var/lib/snapd", "/var/lib/snapd/snap/bin", "/tmp/it's", "/root/x", "/nope"}
	// GNU coreutils 8.30 on Rocky 8 (9.10 on Amazon Linux 2027 prints the same)
	gnu := `ls: cannot access '/var/lib/snapd': No such file or directory
ls: cannot access '/var/lib/snapd/snap/bin': No such file or directory
ls: cannot access "/tmp/it's": No such file or directory
ls: cannot access '/root/x': Permission denied
`
	assert.Equal(t, map[string]bool{"/var/lib/snapd": true, "/var/lib/snapd/snap/bin": true, "/tmp/it's": true},
		parseLsAbsent(gnu, paths))
	// busybox, and macOS
	assert.Equal(t, map[string]bool{"/nope": true}, parseLsAbsent("ls: /nope: No such file or directory\n", paths))
	// GNU coreutils before 8.25 did not quote
	assert.Equal(t, map[string]bool{"/nope": true}, parseLsAbsent("ls: cannot access /nope: No such file or directory\n", paths))
	// a path that was not asked for, or another error, is not absent
	assert.Empty(t, parseLsAbsent("ls: cannot access '/other': No such file or directory\n", paths))
	assert.Empty(t, parseLsAbsent("ls: cannot access '/nope': Input/output error\n", paths))
	assert.Empty(t, parseLsAbsent("", paths))
}

// A read that returns no bytes from a file ls reports as non-empty cannot
// tell a script from a binary.
func TestEmptyHeadOfNonEmptyFileIsUnreadable(t *testing.T) {
	x := fakeProbe(al2027NodeTarball, al2027Heads(), al2027SecurePath)
	x.head = func(string) ([]byte, error) { return []byte{}, nil }
	_, reason := trustedExecutable("/opt/tools/envtool", x, 0)
	assert.Equal(t, "read nothing from /opt/tools/envtool, which holds 60 bytes", reason)

	// an empty file is not a script
	x = fakeProbe(al2027NodeTarball+"-rwxr-xr-x.  1    0    0         0 Oct  3 16:30 /opt/tools/empty\n",
		map[string]string{"/opt/tools/empty": ""}, al2027SecurePath)
	_, reason = trustedExecutable("/opt/tools/empty", x, 0)
	assert.Empty(t, reason)
}

// An unprivileged scan may run a file it is denied reading, but not one
// whose read failed for any other reason.
func TestNonRootReadFailureOtherThanPermission(t *testing.T) {
	x := fakeProbe(al2027NodeTarball, al2027Heads(), al2027SecurePath)
	x.uid = 1000
	x.head = func(string) ([]byte, error) { return nil, errors.New("i/o timeout") }
	_, reason := trustedExecutable("/opt/tools/elftool", x, 0)
	assert.Equal(t, "i/o timeout", reason)
}

// The kernel applies ".." to the directory a link led to, not to the text.
func TestDotDotAfterLink(t *testing.T) {
	lstat, _ := fakeLstat(`drwxr-xr-x 5 0 0 0 Oct  3 16:30 /
drwxr-xr-x 3 0 0 0 Oct  3 16:30 /a
lrwxrwxrwx 1 0 0 9 Oct  3 16:30 /a/sub -> /home/u/d
lrwxrwxrwx 1 0 0 16 Oct  3 16:30 /a/tool -> sub/../bin/tool
drwxr-xr-x 2 0 0 0 Oct  3 16:30 /a/bin
-rwxr-xr-x 1 0 0 9 Oct  3 16:30 /a/bin/tool
drwxr-xr-x 3 0 0 0 Oct  3 16:30 /home
drwxr-xr-x 3 0 0 0 Oct  3 16:30 /home/u
drwxr-xr-x 2 1000 1000 0 Oct  3 16:30 /home/u/d
drwxr-xr-x 2 1000 1000 0 Oct  3 16:30 /home/u/bin
-rwxr-xr-x 1 1000 1000 9 Oct  3 16:30 /home/u/bin/tool
-rwxr-xr-x 1 0 0 9 Oct  3 16:30 /a/file
`)
	target, reason := trustedResolution("/a/tool", 0, lstat)
	assert.Equal(t, "/home/u/bin/tool", target)
	assert.Equal(t, "/home/u/d is owned by uid 1000 with mode drwxr-xr-x", reason)

	// ".." in the path that is asked for is not collapsed either
	target, reason = trustedResolution("/a/sub/../bin/tool", 0, lstat)
	assert.Equal(t, "/home/u/bin/tool", target)
	assert.NotEmpty(t, reason)

	// ".." with no link ahead of it, and at /
	target, reason = trustedResolution("/../a/bin/../bin/tool", 0, lstat)
	assert.Equal(t, "/a/bin/tool", target)
	assert.Empty(t, reason)

	// ".." after a file is not a directory, as for the kernel
	_, reason = trustedResolution("/a/file/../bin/tool", 0, lstat)
	assert.Equal(t, "/a/file is not a directory", reason)
}

// env -S splits its string itself, with quotes, escapes and ${VAR}.
func TestEnvSplitStringQuoting(t *testing.T) {
	heads := al2027Heads()
	run := func(shebang string) string {
		heads["/opt/tools/elftool"] = shebang
		x := fakeProbe(al2027NodeTarball, heads, "/usr/bin")
		_, reason := trustedExecutable("/opt/tools/elftool", x, 0)
		return reason
	}
	assert.Equal(t, "env changes PATH", run("#!/usr/bin/env -S \"PATH=/home/u/bin\" bash\n"))
	assert.Equal(t, "env changes PATH", run("#!/usr/bin/env -S 'PATH=/home/u/bin' bash\n"))
	assert.Equal(t, `env -S word X=1\_PATH=/home/u/bin is not understood`, run("#!/usr/bin/env -S X=1\\_PATH=/home/u/bin bash\n"))
	assert.Equal(t, `env -S word "FOO=x" is not understood`, run("#!/usr/bin/env -S \"FOO=x\" bash\n"))
	assert.Equal(t, "env -S word A=${B} is not understood", run("#!/usr/bin/env -S A=${B} bash\n"))
	assert.Equal(t, "env -S word #x is not understood", run("#!/usr/bin/env -S #x bash\n"))
	// plain -S still runs
	assert.Empty(t, run("#!/usr/bin/env -S A=1 bash -e\n"))
}
