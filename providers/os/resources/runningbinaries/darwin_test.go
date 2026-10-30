// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
)

func TestDarwinSystemPath(t *testing.T) {
	assert.True(t, darwinSystemPath("/usr/libexec/logd"))
	assert.True(t, darwinSystemPath("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"))
	// Safari is delivered in a cryptex
	assert.True(t, darwinSystemPath("/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari"))
	assert.False(t, darwinSystemPath("/usr/local/bin/node"))
	assert.False(t, darwinSystemPath("/opt/homebrew/Cellar/node/22.11.0/bin/node"))
	assert.False(t, darwinSystemPath("/Applications/Slack.app/Contents/MacOS/Slack"))
}

func TestParseProcExeDarwin(t *testing.T) {
	// the macOS listing has no /proc to read the running file through
	out := "1\t/sbin/launchd\n410\t/Applications/Slack.app/Contents/MacOS/Slack\n" +
		"412\t/Applications/Slack.app/Contents/MacOS/Slack\n"
	bins, err := parseProcExe(strings.NewReader(out), false)
	require.NoError(t, err)
	assert.Equal(t, []Binary{
		{Path: "/sbin/launchd", Pids: []int64{1}},
		{Path: "/Applications/Slack.app/Contents/MacOS/Slack", Pids: []int64{410, 412}},
	}, bins)
}

func TestListDarwinScript(t *testing.T) {
	// the installed file and the Homebrew-style link a process was started by
	dir := t.TempDir()
	real := filepath.Join(dir, "Cellar", "node", "22.11.0", "bin", "node")
	require.NoError(t, os.MkdirAll(filepath.Dir(real), 0o755))
	require.NoError(t, os.WriteFile(real, nil, 0o755))
	link := filepath.Join(dir, "node")
	require.NoError(t, os.Symlink(real, link))
	realResolved, err := filepath.EvalSymlinks(real)
	require.NoError(t, err)

	// ps right-aligns the pid; a login shell and a process started from
	// the shell's PATH are listed by their name
	stubTool(t, "ps", "printf '    1 /System/Library/CoreServices/launchservicesd\\n  501 -zsh\\n  777 "+link+"\\n  778 /Applications/My App.app/Contents/MacOS/My App\\n  779 node\\n'\n")
	// proc_pidpath, through osascript, is asked for every process, and
	// resolves the login shell and launchservicesd; the others are left to
	// realpath and lsof
	stubTool(t, "osascript", `[ "$1 $2 $3" = "-l JavaScript -e" ] || exit 1
shift 4
[ "$*" = "1 501 777 778 779" ] || exit 1
printf '1\t/System/Library/CoreServices/launchservicesd\n501\t/bin/zsh\n'
`)
	// lsof is asked only for the process with no path that proc_pidpath
	// left, and lists the executable as the first txt entry, before the
	// libraries
	stubTool(t, "lsof", `[ "$7" = "779" ] || exit 1
printf 'p779\nftxt\nn/opt/homebrew/Cellar/node/22.11.0/bin/node\nftxt\nn/usr/lib/dyld\n'
`)

	conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})
	bins, err := listDarwin(conn)
	require.NoError(t, err)
	assert.Equal(t, []Binary{
		{Path: "/System/Library/CoreServices/launchservicesd", Pids: []int64{1}, System: true},
		{Path: "/bin/zsh", Pids: []int64{501}, System: true},
		{Path: realResolved, Pids: []int64{777}},
		// a path realpath cannot resolve is kept as ps printed it
		{Path: "/Applications/My App.app/Contents/MacOS/My App", Pids: []int64{778}},
		{Path: "/opt/homebrew/Cellar/node/22.11.0/bin/node", Pids: []int64{779}},
	}, bins)
}

func TestDarwinPidPathScript(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("proc_pidpath is a macOS call")
	}
	exe, err := os.Executable()
	require.NoError(t, err)
	exe, err = filepath.EvalSymlinks(exe)
	require.NoError(t, err)

	pid := strconv.Itoa(os.Getpid())
	out, err := exec.Command("osascript", "-l", "JavaScript", "-e", darwinPidPathScript, pid, "999999999").Output()
	require.NoError(t, err)
	// a pid that does not exist is left out
	assert.Equal(t, pid+"\t"+exe, strings.TrimSpace(string(out)))
}
