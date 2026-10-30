// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"bufio"
	"io"
	"slices"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// linuxProcExeScript prints one line per process whose executable the
// scanning user can read: the pid and the executable path, tab separated.
//
// The executable comes from the /proc/<pid>/exe link, since the process name
// /proc reports elsewhere is cut to 15 characters and is not a path. Kernel
// threads have no executable, and another user's processes deny the link to
// an unprivileged user; both are skipped, and so is the script's own shell.
//
// A process whose root directory is not the scan's runs inside a container:
// its executable path refers to the container's file system, and the
// container's package database, not the host's, says what owns it. It is
// left out, so a containerised binary is not reported as unowned by the
// host. The root is compared rather than the mount namespace, since systemd
// gives every service with PrivateTmp=, ProtectSystem= and the like a mount
// namespace of its own on the host's root.
//
// One shell loop rather than reading /proc through the file system: over SSH
// every file read is a round trip, and a host runs hundreds of processes.
const linuxProcExeScript = `for d in /proc/[0-9]*; do
  [ "${d#/proc/}" = "$$" ] && continue
  e=$(readlink "$d/exe" 2>/dev/null) || continue
  [ -n "$e" ] || continue
  [ "$d/root/" -ef / ] || continue
  printf '%s\t%s\n' "${d#/proc/}" "$e"
done; exit 0`

// deletedSuffix is what the kernel appends to /proc/<pid>/exe when the file
// the process was started from no longer exists at its path, typically
// because a package upgrade replaced it.
const deletedSuffix = " (deleted)"

func listLinux(conn shared.Connection) ([]Binary, error) {
	cmd, err := runCommand(conn, linuxProcExeScript)
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, commandFailed(cmd, "could not list process executables")
	}
	return parseProcExe(cmd.Stdout, true)
}

// parseProcExe groups "<pid>\t<path>" lines by executable. With fromProc,
// the content of a file that no longer exists at its path is read through
// /proc/<pid>/exe, which still holds it. Every other file is read at its
// path, which is the running file itself: a remote scan reads /proc only by
// copying the whole file, but a path in pieces.
func parseProcExe(r io.Reader, fromProc bool) ([]Binary, error) {
	byPath := map[string]*Binary{}
	var order []string

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		pidField, path, ok := strings.Cut(scanner.Text(), "\t")
		if !ok {
			continue
		}
		pid, err := strconv.ParseInt(pidField, 10, 64)
		if err != nil {
			continue
		}
		path, deleted := strings.CutSuffix(path, deletedSuffix)
		// An anonymous executable has no path to own or read: a memfd
		// shows as "/memfd:<name>".
		if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "/memfd:") {
			continue
		}

		b, ok := byPath[path]
		if !ok {
			b = &Binary{Path: path}
			byPath[path] = b
			order = append(order, path)
		}
		b.Pids = append(b.Pids, pid)
		if fromProc && deleted && b.ContentPath == "" {
			b.ContentPath = "/proc/" + pidField + "/exe"
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	res := make([]Binary, 0, len(order))
	for _, path := range order {
		b := byPath[path]
		slices.Sort(b.Pids)
		res = append(res, *b)
	}
	return res, nil
}
