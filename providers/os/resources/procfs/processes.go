// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package procfs

import (
	"bufio"
	"bytes"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

type LinuxProcess struct {
	Pid     int64               `json:"pid"`
	Cmdline string              `json:"cmdline"`
	Status  *LinuxProcessStatus `json:"status"`
}

type LinuxProcessStatus struct {
	// lets assume pids are always unsigned, linux returns -1 on unsuccessful forks but that
	// is never becoming a real process
	Pid        int64  `json:"pid"`        // process id
	PPid       int64  `json:"ppid"`       // process id of the parent process
	Executable string `json:"executable"` // filename of the executable
	State      string `json:"state"`
	Tgid       int64  `json:"tgid"` // thread group ID
	Ngid       int64  `json:"ngid"` // NUMA group ID (0 if none)
}

var LINUX_PROCESS_STATUS_REGEX = regexp.MustCompile(`^(.*):\s*(.*)$`)

func ParseProcessStatus(input io.Reader) (*LinuxProcessStatus, error) {
	lps := &LinuxProcessStatus{}
	var err error
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		m := LINUX_PROCESS_STATUS_REGEX.FindStringSubmatch(line)

		if m == nil {
			log.Warn().Str("entry", line).Msg("ignore process status entry")
			continue
		}

		key := m[1]
		value := m[2]
		switch key {
		case "Name":
			lps.Executable = value
		case "State": // state (R is running, S is sleeping, D is sleeping
			// in an uninterruptible wait, Z is zombie, T is traced or stopped)
			lps.State = value
		case "Pid":
			if lps.Pid, err = strconv.ParseInt(value, 10, 64); err != nil {
				log.Warn().Err(err).Str("key", key).Msg("process> could not parse value")
				continue
			}
		case "PPid":
			if lps.PPid, err = strconv.ParseInt(value, 10, 64); err != nil {
				log.Warn().Err(err).Str("key", key).Msg("process> could not parse value")
				continue
			}
		case "Tgid":
			if lps.Tgid, err = strconv.ParseInt(value, 10, 64); err != nil {
				log.Warn().Err(err).Str("key", key).Msg("process> could not parse value")
				continue
			}
		case "Ngid":
			if lps.Ngid, err = strconv.ParseInt(value, 10, 64); err != nil {
				log.Warn().Err(err).Str("key", key).Msg("process> could not parse value")
				continue
			}
		case "Uid": // Real, effective, saved set, and  file system UIDs

		case "Gid": // Real, effective, saved set, and  file system GIDs

		case "Umask", "TracerPid", "FDSize", "Groups", "VmPeak", "VmSize", "VmLck", "VmPin",
			"VmHWM", "VmRSS", "RssAnon", "RssFile", "RssShmem", "VmData", "VmStk", "VmExe", "VmLib",
			"VmPTE", "VmSwap", "Threads", "SigQ", "SigPnd", "ShdPnd", "SigBlk", "SigIgn", "SigCgt",
			"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "Seccomp", "Cpus_allowed", "Cpus_allowed_list",
			"Mems_allowed", "Mems_allowed_list", "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches":
			// known, nothing to do yet
		default:
			log.Debug().Str("key", key).Msg("process status key is not handled")
		}
	}

	// parse status via
	return lps, nil
}

func ParseProcessCmdline(content io.Reader) (string, error) {
	data, err := io.ReadAll(content)
	if err != nil {
		return "", err
	}

	parts := bytes.Split(data, []byte{0})
	var strParts []string
	for _, p := range parts {
		s := strings.TrimSpace(string(p))
		if s != "" {
			strParts = append(strParts, s)
		}
	}

	return strings.Join(strParts, " "), nil
}

// ParseProcessArgv splits /proc/<pid>/cmdline into the process's argv. The
// kernel separates arguments with NUL, so an argument that contains spaces
// stays one element, unlike in the space-joined command line. Empty arguments
// between others are kept; the terminating NUL, and the NUL padding a process
// leaves after rewriting its title, are not arguments. A kernel thread has an
// empty cmdline and no argv.
func ParseProcessArgv(data []byte) []string {
	parts := strings.Split(string(data), "\x00")
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return nil
	}
	return parts
}
