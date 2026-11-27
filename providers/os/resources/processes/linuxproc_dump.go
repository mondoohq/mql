// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// procDumpCommand reads the given processes, or every process when none is
// given, in one command. For each it prints
//
//	P<pid>\0<cmdline in base64>\0<comm>\0<the Name and State lines of status>\0
//
// cmdline is encoded because it holds NUL-separated arguments, which can be
// empty; comm and the status lines hold no NUL. The shell skips itself ($$):
// it is the scan's own command, not a process of the target. A process that
// exits while it is read leaves an empty status, see parseProcDump.
//
// POSIX sh, base64, tr, sed and cat, so it runs on BusyBox as well. Without
// base64 it exits 4, and the caller reads /proc file by file instead.
//
// The pids are integers so that nothing but digits reaches the shell.
func procDumpCommand(pids ...int64) string {
	dirs := "[0-9]*"
	if len(pids) > 0 {
		names := make([]string, len(pids))
		for i, pid := range pids {
			names[i] = strconv.FormatInt(pid, 10)
		}
		dirs = strings.Join(names, " ")
	}
	return `command -v base64 >/dev/null 2>&1 || exit 4; cd /proc || exit 3; ` +
		`for d in ` + dirs + `; do ` +
		`[ "$d" = "$$" ] && continue; [ -d "$d" ] || continue; ` +
		`printf 'P%s\0' "$d"; ` +
		`base64 < "$d/cmdline" 2>/dev/null | tr -d '\n'; printf '\0'; ` +
		`cat "$d/comm" 2>/dev/null; printf '\0'; ` +
		`sed -n '/^Name:/p;/^State:/p' "$d/status" 2>/dev/null; printf '\0'; ` +
		`done`
}

// dumpProcesses reads the given processes, or every process when none is
// given, with procDumpCommand.
func (lpm *LinuxProcManager) dumpProcesses(pids ...int64) ([]*OSProcess, error) {
	cmd, err := lpm.conn.RunCommand(procDumpCommand(pids...))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, fmt.Errorf("reading /proc exited with %d", cmd.ExitStatus)
	}
	return parseProcDump(cmd.Stdout)
}

// parseProcDump reads the output of procDumpCommand. A process with an empty
// status exited while it was read and is left out, as List leaves out a
// process whose files are gone.
func parseProcDump(r io.Reader) ([]*OSProcess, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	res := []*OSProcess{}
	if len(data) == 0 {
		return res, nil
	}
	// every field ends in a NUL, so a complete dump ends in one and holds
	// four fields per process: anything else is not the dump (an error
	// message) or was cut short
	fields := strings.Split(string(data), "\x00")
	if fields[len(fields)-1] != "" || (len(fields)-1)%4 != 0 {
		return nil, fmt.Errorf("incomplete /proc dump")
	}
	for i := 0; i+4 < len(fields); i += 4 {
		entry, cmdline64, comm, status := fields[i], fields[i+1], fields[i+2], fields[i+3]
		if !strings.HasPrefix(entry, "P") {
			return nil, fmt.Errorf("unexpected /proc dump entry %q", entry)
		}
		pid, err := strconv.ParseInt(entry[1:], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("unexpected /proc dump entry %q", entry)
		}
		if strings.TrimSpace(status) == "" {
			continue
		}
		cmdline, err := base64.StdEncoding.DecodeString(cmdline64)
		if err != nil {
			return nil, fmt.Errorf("cannot decode the cmdline of process %d: %w", pid, err)
		}
		proc, err := newProcess(pid, cmdline, []byte(comm), strings.NewReader(status))
		if err != nil {
			return nil, err
		}
		res = append(res, proc)
	}
	return res, nil
}

// ParseSocketInode extracts the inode number from a /proc/*/fd/* symlink target.
// Returns -1 if the link target is not a socket (e.g. "pipe:[...]", "/dev/null").
func ParseSocketInode(link string) (int64, error) {
	if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
		return -1, nil
	}
	inodeStr := link[len("socket:[") : len(link)-1]
	return strconv.ParseInt(inodeStr, 10, 64)
}

// socketInodesDumpCommand lists the open file descriptors of every process in
// one command: a "P<pid>" line, then `ls -l` of its fd directory, where a
// socket shows as "<fd> -> socket:[<inode>]". GNU find's -lname and -printf,
// which UnixProcessManager uses, are missing from BusyBox (Alpine) and from
// images without findutils; ls is not.
//
// A process whose descriptors cannot be resolved lists none. That is the case
// for another user's process when the command does not run as root, and in a
// container even as root: resolving another user's fd links takes
// CAP_SYS_PTRACE, which docker does not grant by default, so ls prints the
// descriptors without their targets. ls failing for one process does not fail
// the listing.
const socketInodesDumpCommand = `cd /proc || exit 3; ` +
	`for d in [0-9]*; do ` +
	`[ "$d" = "$$" ] && continue; [ -d "$d" ] || continue; ` +
	`printf 'P%s\n' "$d"; ls -l "$d/fd" 2>/dev/null || true; ` +
	`done`

// dumpSocketInodes reads the socket inodes of every process with
// socketInodesDumpCommand.
func (lpm *LinuxProcManager) dumpSocketInodes() (map[int64]plugin.TValue[[]int64], error) {
	cmd, err := lpm.conn.RunCommand(socketInodesDumpCommand)
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, fmt.Errorf("reading /proc exited with %d", cmd.ExitStatus)
	}
	return parseSocketInodesDump(cmd.Stdout)
}

// parseSocketInodesDump reads the output of socketInodesDumpCommand into the
// socket inodes of each process, keyed by pid. Every listed process has an
// entry, an empty one when it holds no socket.
func parseSocketInodesDump(r io.Reader) (map[int64]plugin.TValue[[]int64], error) {
	res := map[int64]plugin.TValue[[]int64]{}
	pid := int64(-1)
	var inodes []int64
	flush := func() {
		if pid >= 0 {
			res[pid] = plugin.TValue[[]int64]{Data: inodes, State: plugin.StateIsSet}
		}
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if rest, ok := strings.CutPrefix(line, "P"); ok {
			if p, err := strconv.ParseInt(rest, 10, 64); err == nil {
				flush()
				pid, inodes = p, []int64{}
				continue
			}
		}
		_, target, ok := strings.Cut(line, " -> ")
		if !ok || pid < 0 {
			continue
		}
		inode, err := ParseSocketInode(strings.TrimSpace(target))
		if err != nil || inode < 0 {
			continue
		}
		inodes = append(inodes, inode)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flush()
	return res, nil
}
