// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"bytes"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/procfs"
)

type LinuxProcManager struct {
	conn shared.Connection
}

func (lpm *LinuxProcManager) Name() string {
	return "Linux Process Manager"
}

// hiddenProcesses returns a HiddenProcessesError when /proc is mounted with
// hidepid and the scanner may not read other users' processes.
func (lpm *LinuxProcManager) hiddenProcesses() error {
	var text strings.Builder
	for _, path := range procSelfFiles {
		data, err := afero.ReadFile(lpm.conn.FileSystem(), path)
		if err != nil {
			log.Debug().Err(err).Str("path", path).Msg("mql[processes]> cannot read, assuming every process is visible")
			return nil
		}
		text.Write(data)
		text.WriteByte('\n')
	}
	return procVisibility(text.String())
}

func (lpm *LinuxProcManager) List() ([]*OSProcess, error) {
	// Under hidepid a non-root scan finds only its own pids in /proc, and
	// that subset would read as the complete process list.
	if err := lpm.hiddenProcesses(); err != nil {
		return nil, err
	}

	// get all subdirectories of /proc, filter by numbers
	f, err := lpm.conn.FileSystem().Open("/proc")
	if err != nil {
		return nil, errors.WithMessage(err, "failed to access /proc")
	}

	dirs, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	res := []*OSProcess{}
	for i := range dirs {
		// we only parse directories that are numbers
		pid, err := strconv.ParseInt(dirs[i], 10, 64)
		if err != nil {
			continue
		}

		pidPath := filepath.Join("/proc", dirs[i])

		// collect process info
		proc, err := lpm.processInfo(pid, pidPath)
		if err != nil {
			log.Warn().Err(err).Int64("pid", pid).Msg("mql[processes]> could not retrieve process information")
			continue
		}

		proc.SocketInodes, proc.SocketInodesError = lpm.procSocketInods(pid, pidPath)

		res = append(res, proc)
	}

	return res, nil
}

// processInfo gathers cmdline, status for a process without socket inodes.
//
// It does not verify that the pid still exists: callers that enumerate pids
// from /proc (List) already know the directory exists, so re-stating it here
// would be a redundant syscall per process. The single-pid entry point
// (Process) checks existence itself before calling in.
func (lpm *LinuxProcManager) processInfo(pid int64, pidPath string) (*OSProcess, error) {
	cmdlineData, err := afero.ReadFile(lpm.conn.FileSystem(), filepath.Join(pidPath, "cmdline"))
	if err != nil {
		return nil, err
	}
	argv := procfs.ParseProcessArgv(cmdlineData)
	if argv == nil {
		// A kernel thread has an empty cmdline: its argv was read and is
		// empty, which flags must not take for an argv it still has to read.
		argv = []string{}
	}

	cmdline, err := procfs.ParseProcessCmdline(bytes.NewReader(cmdlineData))
	if err != nil {
		return nil, err
	}

	if cmdline == "" {
		commf, err := lpm.conn.FileSystem().Open(filepath.Join(pidPath, "comm"))
		if err != nil {
			return nil, err
		}
		defer commf.Close()

		cmdline, err = procfs.ParseProcessCmdline(commf)
		if err != nil {
			return nil, err
		}
	}

	statusf, err := lpm.conn.FileSystem().Open(filepath.Join(pidPath, "status"))
	if err != nil {
		return nil, err
	}
	defer statusf.Close()

	status, err := procfs.ParseProcessStatus(statusf)
	if err != nil {
		return nil, err
	}

	return &OSProcess{
		Pid:        pid,
		Executable: status.Executable,
		State:      status.State,
		Command:    cmdline,
		Argv:       argv,
	}, nil
}

// Exists checks that the pid directory exists. A pid that /proc hides from
// the scanner (hidepid) is reported as a HiddenProcessesError, not as absent.
func (lpm *LinuxProcManager) Exists(pid int64) (bool, error) {
	pidPath := filepath.Join("/proc", strconv.FormatInt(pid, 10))
	afutil := afero.Afero{Fs: lpm.conn.FileSystem()}
	exists, err := afutil.Exists(pidPath)
	if err != nil || exists {
		return exists, err
	}
	if hidden := lpm.hiddenProcesses(); hidden != nil {
		return false, hidden
	}
	return false, nil
}

func (lpm *LinuxProcManager) Process(pid int64) (*OSProcess, error) {
	pidPath := filepath.Join("/proc", strconv.FormatInt(pid, 10))

	// The caller supplies an arbitrary pid that may not exist, so verify it
	// before reading. List() skips this check because its pids come straight
	// from the /proc enumeration.
	exists, err := lpm.Exists(pid)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("process " + strconv.FormatInt(pid, 10) + " does not exist: " + pidPath)
	}

	proc, err := lpm.processInfo(pid, pidPath)
	if err != nil {
		// hidepid=noaccess lists every pid but refuses its files
		if hidden := lpm.hiddenProcesses(); hidden != nil {
			return nil, hidden
		}
		return nil, err
	}

	proc.SocketInodes, proc.SocketInodesError = lpm.procSocketInods(pid, pidPath)

	return proc, nil
}

func (lpm *LinuxProcManager) ListSocketInodesByProcess() (map[int64]plugin.TValue[[]int64], error) {
	return nil, nil
}
