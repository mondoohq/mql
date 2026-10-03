// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package filesfind

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireGNUFind skips unless the local find understands -xtype and -prune
// like GNU find (GNU findutils, or bfs as on macOS runners).
func requireGNUFind(t *testing.T) {
	t.Helper()
	out, err := exec.Command("find", "--version").CombinedOutput()
	if err != nil || (!strings.Contains(string(out), "GNU findutils") && !strings.Contains(string(out), "bfs")) {
		t.Skip("needs GNU-compatible find")
	}
}

func writeSuid(t *testing.T, p string) {
	t.Helper()
	require.NoError(t, os.WriteFile(p, nil, 0o755))
	require.NoError(t, os.Chmod(p, 0o755|os.ModeSetuid))
}

func runFind(t *testing.T, cmd string) []string {
	t.Helper()
	out, err := exec.Command("sh", "-c", cmd).Output()
	require.NoError(t, err, cmd)
	lines := strings.Fields(string(out))
	sort.Strings(lines)
	return lines
}

// On a usr-merged host /bin, /sbin and /lib are symlinks into /usr. The prune
// that keeps the walk out of symlinked directories (#11005) also pruned the
// start path when it was such a link, so files.find(from: "/bin") found
// nothing, and every suid check that starts there passed on an empty list.
func TestBuildFilesFindCmd_SymlinkStartIsWalked(t *testing.T) {
	requireGNUFind(t)

	root := t.TempDir()
	usrBin := filepath.Join(root, "usr", "bin")
	require.NoError(t, os.MkdirAll(filepath.Join(usrBin, "sub"), 0o755))
	writeSuid(t, filepath.Join(usrBin, "su"))
	require.NoError(t, os.WriteFile(filepath.Join(usrBin, "ls"), nil, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(usrBin, "sub", "f"), nil, 0o644))
	// a usr-merge style start path
	require.NoError(t, os.Symlink("usr/bin", filepath.Join(root, "bin")))
	// a symlinked directory below the start must still not be walked into
	require.NoError(t, os.MkdirAll(filepath.Join(root, "elsewhere"), 0o755))
	writeSuid(t, filepath.Join(root, "elsewhere", "hidden"))
	require.NoError(t, os.Symlink("../../elsewhere", filepath.Join(usrBin, "linkdir")))
	// glob characters in the start path must not break the start-path match
	weird := filepath.Join(root, "we*rd[1]")
	require.NoError(t, os.Symlink("usr/bin", weird))

	bin := filepath.Join(root, "bin")
	suid := runFind(t, BuildFilesFindCmd(bin, false, "file", "", 0o4000, "", nil, true))
	assert.Equal(t, []string{filepath.Join(bin, "su")}, suid)

	all := runFind(t, BuildFilesFindCmd(bin, false, "", "", 0o777, "", nil, true))
	assert.Equal(t, []string{
		bin,
		filepath.Join(bin, "linkdir"),
		filepath.Join(bin, "ls"),
		filepath.Join(bin, "su"),
		filepath.Join(bin, "sub"),
		filepath.Join(bin, "sub", "f"),
	}, all)

	weirdSuid := runFind(t, BuildFilesFindCmd(weird, false, "file", "", 0o4000, "", nil, true))
	assert.Equal(t, []string{filepath.Join(weird, "su")}, weirdSuid)

	// a start path that is a real directory is unchanged
	real := runFind(t, BuildFilesFindCmd(usrBin, false, "file", "", 0o4000, "", nil, true))
	assert.Equal(t, []string{filepath.Join(usrBin, "su")}, real)
}
