// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
