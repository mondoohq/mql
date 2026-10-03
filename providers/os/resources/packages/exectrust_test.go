// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
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

// fakeLstat answers from captured ls output and counts the calls.
func fakeLstat(out string) (func([]string) map[string]pathEntry, *int) {
	all := parseLsLong(out)
	calls := 0
	return func(paths []string) map[string]pathEntry {
		calls++
		res := map[string]pathEntry{}
		for _, p := range paths {
			if e, ok := all[p]; ok {
				res[p] = e
			}
		}
		return res
	}, &calls
}

func TestParseLsLong(t *testing.T) {
	entries := parseLsLong(rhel7NodeTarball + "ls: cannot access /nonexist: No such file or directory\n")
	require.Contains(t, entries, "/")
	assert.Equal(t, pathEntry{mode: "dr-xr-xr-x", uid: 0}, entries["/"])
	assert.Equal(t, int64(1000), entries["/usr/local/lib/node_modules"].uid)
	assert.Equal(t, "../lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe", entries["/usr/local/bin/claude"].link)
	assert.True(t, entries["/usr/local/bin/claude"].isLink())
	assert.True(t, entries["/tmp"].writableByOthers())
	assert.False(t, entries["/usr/local/bin"].writableByOthers())
	assert.NotContains(t, entries, "/nonexist")

	// macOS: ACL/xattr markers after the mode, a group-writable Homebrew bin
	mac := parseLsLong("drwxrwxr-x  563 501  80  18016 Oct  2 08:34 /opt/homebrew/bin\nlrwxr-xr-x@   1 0    0      11 Sep  3 03:34 /tmp -> private/tmp\n")
	assert.Equal(t, int64(501), mac["/opt/homebrew/bin"].uid)
	assert.True(t, mac["/opt/homebrew/bin"].writableByOthers())
	assert.Equal(t, "private/tmp", mac["/tmp"].link)
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

func TestPathPrefixes(t *testing.T) {
	assert.Equal(t, []string{"/"}, pathPrefixes("/"))
	assert.Equal(t, []string{"/", "/usr", "/usr/bin", "/usr/bin/x"}, pathPrefixes("/usr/bin/x"))
}
