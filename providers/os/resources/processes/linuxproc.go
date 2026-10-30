// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"bytes"
	"io"
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

func (lpm *LinuxProcManager) List() ([]*OSProcess, error) {
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
	cmdlinef, err := lpm.conn.FileSystem().Open(filepath.Join(pidPath, "cmdline"))
	if err != nil {
		return nil, err
	}
	defer cmdlinef.Close()

	cmdlineData, err := io.ReadAll(cmdlinef)
	if err != nil {
		return nil, err
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
		Executable: fullExecutableName(status.Executable, cmdlineData),
		State:      status.State,
		Command:    cmdline,
	}, nil
}

// taskCommLen is the length the kernel cuts a process name to in
// /proc/<pid>/status and /proc/<pid>/comm: TASK_COMM_LEN (16) less the
// terminating NUL.
const taskCommLen = 15

// fullExecutableName returns the process name from /proc/<pid>/status, or,
// when the kernel cut it to taskCommLen characters, the base name of the
// command's first argument that it is the start of. kube-controller-manager
// is "kube-controller" in status, and "/usr/local/bin/kube-controller-manager"
// in cmdline. A first argument the name does not start (a process that
// rewrote its title, such as "nginx: master process") leaves the name as it
// is, as does an empty cmdline (kernel threads).
func fullExecutableName(name string, cmdline []byte) string {
	if len(name) != taskCommLen {
		return name
	}
	argv0, _, _ := bytes.Cut(cmdline, []byte{0})
	base := string(argv0)
	if _, after, ok := strings.CutLast(base, "/"); ok {
		base = after
	}
	if len(base) > len(name) && strings.HasPrefix(base, name) {
		return base
	}
	return name
}

// check that the pid directory exists
func (lpm *LinuxProcManager) Exists(pid int64) (bool, error) {
	pidPath := filepath.Join("/proc", strconv.FormatInt(pid, 10))
	afutil := afero.Afero{Fs: lpm.conn.FileSystem()}
	return afutil.Exists(pidPath)
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
		return nil, err
	}

	proc.SocketInodes, proc.SocketInodesError = lpm.procSocketInods(pid, pidPath)

	return proc, nil
}

func (lpm *LinuxProcManager) ListSocketInodesByProcess() (map[int64]plugin.TValue[[]int64], error) {
	return nil, nil
}
