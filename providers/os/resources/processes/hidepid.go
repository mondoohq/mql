// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"fmt"
	"strconv"
	"strings"
)

// procSelfFiles are read together, by one reader, so the identity in
// /proc/self/status is the one that reads /proc: the scanner itself, or the
// elevated command that reads files for it.
var procSelfFiles = []string{"/proc/self/mounts", "/proc/self/status"}

// capSysPtrace is CAP_SYS_PTRACE's bit in the CapEff mask. It lets a process
// read every other process under any hidepid mode.
const capSysPtrace = 19

// HiddenProcessesError reports that /proc is mounted with hidepid and the
// scanner may not read other users' processes, so any process list it builds
// is the subset of its own processes.
type HiddenProcessesError struct {
	// Mode is the hidepid value as /proc/mounts prints it ("2", "invisible").
	Mode string
	Uid  int64
}

func (e *HiddenProcessesError) Error() string {
	return fmt.Sprintf("/proc is mounted with hidepid=%s, so uid %d cannot see other users' processes; scan as root or as a member of the group set by the /proc gid= mount option", e.Mode, e.Uid)
}

// procVisibility decides from the /proc/self/mounts and /proc/self/status
// lines of the reader (in one text, in either order) whether hidepid hides
// other users' processes from it. It mirrors the kernel's
// has_pid_permissions: hidepid=1/noaccess, 2/invisible and 4/ptraceable
// restrict, a member of the gid= group (root's group 0 by default) is exempt
// except under ptraceable, and CAP_SYS_PTRACE passes the ptrace check that
// remains. It returns nil when nothing is hidden, or when the reader's
// identity cannot be read.
func procVisibility(procSelf string) error {
	mode := ""
	pidGid := int64(0)
	var euid, fsgid int64 = -1, -1
	var groups []int64
	var capEff uint64
	haveCaps := false

	for _, line := range strings.Split(procSelf, "\n") {
		if key, val, ok := strings.Cut(line, ":\t"); ok {
			fields := strings.Fields(val)
			switch key {
			case "Uid":
				if len(fields) >= 2 {
					euid, _ = strconv.ParseInt(fields[1], 10, 64)
				}
			case "Gid":
				if len(fields) >= 4 {
					fsgid, _ = strconv.ParseInt(fields[3], 10, 64)
				}
			case "Groups":
				for _, g := range fields {
					if n, err := strconv.ParseInt(g, 10, 64); err == nil {
						groups = append(groups, n)
					}
				}
			case "CapEff":
				if len(fields) == 1 {
					if n, err := strconv.ParseUint(fields[0], 16, 64); err == nil {
						capEff, haveCaps = n, true
					}
				}
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != "/proc" || fields[2] != "proc" {
			continue
		}
		// the last /proc mount is the one in effect
		mode, pidGid = "", 0
		for _, opt := range strings.Split(fields[3], ",") {
			switch {
			case strings.HasPrefix(opt, "hidepid="):
				mode = strings.TrimPrefix(opt, "hidepid=")
			case strings.HasPrefix(opt, "gid="):
				pidGid, _ = strconv.ParseInt(strings.TrimPrefix(opt, "gid="), 10, 64)
			}
		}
	}

	ptraceable := false
	switch mode {
	case "1", "noaccess", "2", "invisible":
	case "4", "ptraceable":
		ptraceable = true
	default:
		// absent, 0 or off: every process is visible
		return nil
	}

	if euid < 0 || fsgid < 0 || !haveCaps {
		return nil
	}
	if capEff&(1<<capSysPtrace) != 0 {
		return nil
	}
	if !ptraceable {
		if fsgid == pidGid {
			return nil
		}
		for _, g := range groups {
			if g == pidGid {
				return nil
			}
		}
	}
	return &HiddenProcessesError{Mode: mode, Uid: euid}
}
