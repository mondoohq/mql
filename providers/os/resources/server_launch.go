// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path"
	"strconv"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/tar"
	"go.mondoo.com/mql/providers/os/resources/serverlaunch"
)

// serverLaunchSpec says how to recognize a server's processes.
type serverLaunchSpec struct {
	// Names are the process names (comm) the server runs as, which pgrep
	// matches. Names[0] is also the program an image's entrypoint script
	// passes options to (see serverlaunch.ImageArgv).
	Names []string
	// IsServer reports whether a command line starts the server. It
	// defaults to argv[0]'s base name being one of Names.
	IsServer func(argv []string) bool
	// Env asks for the environment as well.
	Env bool
}

func (s serverLaunchSpec) isServer() func(argv []string) bool {
	if s.IsServer != nil {
		return s.IsServer
	}
	return serverlaunch.IsProgram(s.Names...)
}

// serverLaunchSource says where a serverLaunch was read from.
type serverLaunchSource string

const (
	// serverLaunchProcess is a running process, read from /proc.
	serverLaunchProcess serverLaunchSource = "process"
	// serverLaunchImage is the configuration of a scanned container image.
	serverLaunchImage serverLaunchSource = "image"
)

// serverLaunch is how a server was started.
type serverLaunch struct {
	Source serverLaunchSource
	// Pid is the master process, 0 for an image.
	Pid int
	// Argv is the command line, argv[0] included.
	Argv []string
	// Dir is the working directory relative paths on the command line
	// resolve against, "" when it is not known.
	Dir string
	// Env is the environment, nil when it was not asked for or could not be
	// read.
	Env map[string]string
	// EnvErr is why the environment of a running process could not be read:
	// /proc/<pid>/environ is only readable by the process's own user and
	// root.
	EnvErr error
}

// imageLauncher is a connection that scans a container image and knows the
// process the image starts.
type imageLauncher interface {
	LaunchConfig() *tar.ImageConfig
}

// findServerLaunches returns how the server is started where no unit or pid
// file says so: the command line (and, when asked, the environment) of every
// running master process, lowest pid first, or else the process a scanned
// container image starts. Official container images start servers without a
// unit and often without a pid file, with their options on the command line
// (`haproxy -f /opt/alt.cfg`) or in the environment (OLLAMA_HOST). It returns
// nil when neither applies.
func findServerLaunches(runtime *plugin.Runtime, spec serverLaunchSpec) []serverLaunch {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return nil
	}
	afs := &afero.Afero{Fs: conn.FileSystem()}
	if launches := runningServerLaunches(runtime, conn, afs, spec); len(launches) > 0 {
		return launches
	}
	if l := imageServerLaunch(conn, spec); l != nil {
		return []serverLaunch{*l}
	}
	return nil
}

// runningServerLaunches reads the master processes of the server from /proc.
// Where commands run, pgrep narrows the processes to read; where it cannot
// run (no command support, or an image without procps), every /proc entry
// is read. A process whose command line cannot be read is skipped: it may be
// gone by now. A /proc without command lines (AIX) is not walked: ps lists
// the processes instead, in one command rather than one read per process.
func runningServerLaunches(runtime *plugin.Runtime, conn shared.Connection, afs *afero.Afero, spec serverLaunchSpec) []serverLaunch {
	var procs []serverlaunch.Process
	pids, listed := pgrepPids(runtime, conn, spec.Names)
	switch {
	case listed:
		procs = procfsProcesses(afs, pids)
	case hasProcfsCmdlines(afs):
		entries, err := afs.ReadDir("/proc")
		if err != nil {
			return nil
		}
		for _, e := range entries {
			pids = append(pids, e.Name())
		}
		procs = procfsProcesses(afs, pids)
	default:
		procs = psProcesses(runtime, conn)
	}

	masters := serverlaunch.Masters(procs, spec.isServer())
	out := make([]serverLaunch, 0, len(masters))
	for _, m := range masters {
		l := serverLaunch{Source: serverLaunchProcess, Pid: m.Pid, Argv: m.Argv}
		// /proc/<pid>/cwd, like environ, can only be read for the
		// process's own user and root.
		if lr, ok := afs.Fs.(afero.LinkReader); ok {
			if dir, err := lr.ReadlinkIfPossible(path.Join("/proc", strconv.Itoa(m.Pid), "cwd")); err == nil && path.IsAbs(dir) {
				l.Dir = dir
			}
		}
		if spec.Env {
			raw, err := afs.ReadFile(path.Join("/proc", strconv.Itoa(m.Pid), "environ"))
			if err != nil {
				l.EnvErr = err
			} else {
				l.Env = serverlaunch.ParseEnviron(raw)
			}
		}
		out = append(out, l)
	}
	return out
}

// procfsProcesses reads the command line and parent of each pid from /proc.
func procfsProcesses(afs *afero.Afero, pids []string) []serverlaunch.Process {
	var procs []serverlaunch.Process
	for _, pid := range pids {
		n, err := strconv.Atoi(pid)
		if err != nil {
			continue
		}
		raw, err := afs.ReadFile(path.Join("/proc", pid, "cmdline"))
		if err != nil {
			continue
		}
		p := serverlaunch.Process{Pid: n, Argv: serverlaunch.SplitCmdline(raw)}
		if stat, err := afs.ReadFile(path.Join("/proc", pid, "stat")); err == nil {
			p.PPid, _ = serverlaunch.ParseStatPPid(stat)
		}
		procs = append(procs, p)
	}
	return procs
}

// hasProcfsCmdlines reports whether /proc holds a command line per process,
// as Linux does. pid 1 always runs.
func hasProcfsCmdlines(afs *afero.Afero) bool {
	_, err := afs.Stat("/proc/1/cmdline")
	return err == nil
}

// psProcesses lists the processes with ps, where commands run.
func psProcesses(runtime *plugin.Runtime, conn shared.Connection) []serverlaunch.Process {
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil
	}
	o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData(serverlaunch.PsCommand),
	})
	if err != nil {
		return nil
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Error != nil || exit.Data != 0 {
		return nil
	}
	stdout := cmd.GetStdout()
	if stdout.Error != nil {
		return nil
	}
	return serverlaunch.ParsePs(stdout.Data)
}

// pgrepPids lists the processes named one of names. It reports false when
// pgrep could not answer, and the caller then reads /proc. pgrep exits 1
// when nothing matches, which is an answer.
func pgrepPids(runtime *plugin.Runtime, conn shared.Connection, names []string) ([]string, bool) {
	if len(names) == 0 || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, false
	}
	o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData("pgrep -x '" + strings.Join(names, "|") + "'"),
	})
	if err != nil {
		return nil, false
	}
	cmd := o.(*mqlCommand)
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return nil, false
	}
	switch exit.Data {
	case 0:
		stdout := cmd.GetStdout()
		if stdout.Error != nil {
			return nil, false
		}
		return strings.Fields(stdout.Data), true
	case 1:
		return nil, true
	}
	return nil, false
}

// imageServerLaunch returns the server process a scanned container image
// starts, nil when the connection is not an image or the image starts
// something else.
func imageServerLaunch(conn shared.Connection, spec serverLaunchSpec) *serverLaunch {
	il, ok := conn.(imageLauncher)
	if !ok {
		return nil
	}
	cfg := il.LaunchConfig()
	if cfg == nil {
		return nil
	}
	defaultName := ""
	if len(spec.Names) > 0 {
		defaultName = spec.Names[0]
	}
	argv := serverlaunch.ImageArgv(cfg.Entrypoint, cfg.Cmd, spec.isServer(), defaultName)
	if argv == nil {
		return nil
	}
	l := &serverLaunch{Source: serverLaunchImage, Argv: argv, Dir: cfg.WorkingDir}
	if spec.Env {
		l.Env = serverlaunch.EnvList(cfg.Env)
	}
	return l
}

// resolve makes a path from the command line absolute: relative to the
// working directory, or to / (where systemd starts services, and where a
// container starts without a WORKDIR) when it is not known.
func (l serverLaunch) resolve(p string) string {
	if p == "" || path.IsAbs(p) {
		return p
	}
	dir := l.Dir
	if dir == "" {
		dir = "/"
	}
	return path.Join(dir, p)
}
