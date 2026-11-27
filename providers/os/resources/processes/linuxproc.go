// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"bytes"
	"io"
	"os"
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

// readsProcByCommand reports whether /proc is better read with one command
// than through the filesystem. On a connection that is not local, such as a
// running docker container, every file read under /proc is a remote command
// of its own (docker exec), so listing processes cost several per process.
// Locally a file read is a syscall and stays the cheaper way.
func (lpm *LinuxProcManager) readsProcByCommand() bool {
	return lpm.conn.Type() != shared.Type_Local && lpm.conn.Capabilities().Has(shared.Capability_RunCommand)
}

// List returns every process with its command, executable and state. It does
// not read the processes' open file descriptors: only ports needs those, and
// asks ListSocketInodesByProcess for them.
func (lpm *LinuxProcManager) List() ([]*OSProcess, error) {
	if lpm.readsProcByCommand() {
		procs, err := lpm.dumpProcesses()
		if err == nil {
			return procs, nil
		}
		log.Debug().Err(err).Msg("mql[processes]> could not read /proc in one command, reading it file by file")
	}

	// get all subdirectories of /proc, filter by numbers
	f, err := lpm.conn.FileSystem().Open("/proc")
	if err != nil {
		return nil, errors.WithMessage(err, "failed to access /proc")
	}
	defer f.Close()

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
			// A process that exited between the listing of /proc and the
			// read is gone, not a problem: over docker exec that is every
			// command the scan itself runs.
			if processVanished(err) {
				log.Debug().Err(err).Int64("pid", pid).Msg("mql[processes]> process exited while listing")
				continue
			}
			log.Warn().Err(err).Int64("pid", pid).Msg("mql[processes]> could not retrieve process information")
			continue
		}

		res = append(res, proc)
	}

	return res, nil
}

// processVanished reports whether reading a process failed because it is no
// longer there.
func processVanished(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

// processInfo gathers cmdline, status for a process without socket inodes.
//
// It does not verify that the pid still exists: callers that enumerate pids
// from /proc (List) already know the directory exists, so re-stating it here
// would be a redundant syscall per process. The single-pid entry point
// (Process) checks existence itself before calling in.
func (lpm *LinuxProcManager) processInfo(pid int64, pidPath string) (*OSProcess, error) {
	fs := lpm.conn.FileSystem()
	cmdlineData, err := readProcFile(fs, filepath.Join(pidPath, "cmdline"))
	if err != nil {
		return nil, err
	}
	cmdline, err := procfs.ParseProcessCmdline(bytes.NewReader(cmdlineData))
	if err != nil {
		return nil, err
	}

	// comm is only the command when cmdline has none (a kernel thread, a
	// zombie), so it is only read then
	var comm []byte
	if cmdline == "" {
		if comm, err = readProcFile(fs, filepath.Join(pidPath, "comm")); err != nil {
			return nil, err
		}
	}

	statusf, err := fs.Open(filepath.Join(pidPath, "status"))
	if err != nil {
		return nil, err
	}
	defer statusf.Close()

	return newProcess(pid, cmdlineData, comm, statusf)
}

// readProcFile reads a file under /proc. Unlike afero.ReadFile it does not
// stat the open file for its size, which /proc files do not report and which
// on a filesystem that reads with commands costs one more.
func readProcFile(fs afero.Fs, path string) ([]byte, error) {
	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// newProcess builds a process from the contents of its /proc/<pid> files:
// cmdline as it is, comm, which is the command when cmdline has none, and
// status.
func newProcess(pid int64, cmdlineData []byte, comm []byte, status io.Reader) (*OSProcess, error) {
	cmdline, err := procfs.ParseProcessCmdline(bytes.NewReader(cmdlineData))
	if err != nil {
		return nil, err
	}
	if cmdline == "" {
		if cmdline, err = procfs.ParseProcessCmdline(bytes.NewReader(comm)); err != nil {
			return nil, err
		}
	}

	st, err := procfs.ParseProcessStatus(status)
	if err != nil {
		return nil, err
	}

	return &OSProcess{
		Pid:        pid,
		Executable: fullExecutableName(st.Executable, cmdlineData),
		State:      st.State,
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

	if lpm.readsProcByCommand() {
		procs, err := lpm.dumpProcesses(pid)
		if err == nil {
			if len(procs) == 0 {
				return nil, errors.New("process " + strconv.FormatInt(pid, 10) + " does not exist: " + pidPath)
			}
			return procs[0], nil
		}
		log.Debug().Err(err).Int64("pid", pid).Msg("mql[processes]> could not read the process in one command, reading it file by file")
	}

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

	return lpm.processInfo(pid, pidPath)
}

// ListSocketInodesByProcess returns the inodes of the sockets each process
// holds open, keyed by pid. Finding them resolves every open file descriptor
// of every process, which is why List leaves it to the one caller that needs
// it (ports).
func (lpm *LinuxProcManager) ListSocketInodesByProcess() (map[int64]plugin.TValue[[]int64], error) {
	if lpm.readsProcByCommand() {
		res, err := lpm.dumpSocketInodes()
		if err == nil {
			return res, nil
		}
		log.Debug().Err(err).Msg("mql[processes]> could not read socket inodes in one command, reading them file by file")
	}

	f, err := lpm.conn.FileSystem().Open("/proc")
	if err != nil {
		return nil, errors.WithMessage(err, "failed to access /proc")
	}
	defer f.Close()
	dirs, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	res := map[int64]plugin.TValue[[]int64]{}
	for i := range dirs {
		pid, err := strconv.ParseInt(dirs[i], 10, 64)
		if err != nil {
			continue
		}
		inodes, err := lpm.procSocketInods(pid, filepath.Join("/proc", dirs[i]))
		if err != nil && processVanished(err) {
			continue
		}
		res[pid] = plugin.TValue[[]int64]{Data: inodes, Error: err, State: plugin.StateIsSet}
	}
	return res, nil
}
