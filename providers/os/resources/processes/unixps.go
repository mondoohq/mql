// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kballard/go-shellquote"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

var (
	LINUX_PS_REGEX = regexp.MustCompile(`^\s*([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ].*)?$`)
	UNIX_PS_REGEX  = regexp.MustCompile(`^\s*([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ].*)$`)
	AIX_PS_REGEX   = regexp.MustCompile(`^\s*([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ].*)$`)
	// the same columns with the state (S) before the command
	AIX_PS_STATE_REGEX = regexp.MustCompile(`^\s*([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ].*)$`)

	// "lrwx------ 1 0 0 64 Dec  6 13:56 /proc/1/fd/12 -> socket:[37364]"
	reFindSockets = regexp.MustCompile(
		"^[lrwx-]+\\.?\\s+" +
			"\\d+\\s+" +
			"\\d+\\s+" + // uid
			"\\d+\\s+" + // gid
			"\\d+\\s+" +
			"[^ ]+\\s+" + // month, e.g. Dec
			"\\d+\\s+" + // day
			"\\d+:\\d+\\s+" + // time
			"/proc/(\\d+)/fd/\\d+\\s+" + // path
			"->\\s+" +
			".*socket:\\[(\\d+)\\].*\\s*") // target
)

type ProcessEntry struct {
	Pid     int64
	CPU     string
	Mem     string
	Vsz     string
	Rss     string
	Tty     string
	Stat    string
	Start   string
	Time    string
	Uid     int64
	Command string
}

func (p ProcessEntry) ToOSProcess() *OSProcess {
	executablePath := ""
	args, err := shellquote.Split(p.Command)
	if err == nil && len(args) > 0 {
		executablePath = args[0]
	}

	// Take the last path segment without splitting the whole path first, which
	// allocated a slice of every segment per process just to read one of them.
	// Deliberately not path.Base: it maps "" to "." and "/usr/bin/" to "bin",
	// where this reports "" for both.
	executable := executablePath
	if i := strings.LastIndexByte(executablePath, '/'); i >= 0 {
		executable = executablePath[i+1:]
	}

	return &OSProcess{
		Pid:        p.Pid,
		Command:    p.Command,
		Executable: executable,
		State:      "",
	}
}

func ParseLinuxPsResult(input io.Reader) ([]*ProcessEntry, error) {
	processes := []*ProcessEntry{}
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()

		m := LINUX_PS_REGEX.FindStringSubmatch(line)
		if len(m) != 12 {
			return nil, &ErrorParsingPs{Line: line}
		}
		if m[1] == "PID" {
			// header
			continue
		}

		pid, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			log.Error().Err(err).Msg("cannot parse ps pid " + m[1])
			continue
		}
		uid, err := strconv.ParseInt(m[10], 10, 64)
		if err != nil {
			log.Error().Err(err).Msg("cannot parse ps uid " + m[10])
			continue
		}

		// PID %CPU %MEM    VSZ   RSS TT       STAT  STARTED     TIME   UID COMMAND
		p := &ProcessEntry{
			Pid:     pid,
			CPU:     m[2],
			Mem:     m[3],
			Vsz:     m[4],
			Rss:     m[5],
			Tty:     m[6],
			Stat:    m[7],
			Start:   m[8],
			Time:    m[9],
			Uid:     uid,
			Command: m[11],
		}
		processes = append(processes, p)
	}

	return processes, nil
}

func ParseUnixPsResult(input io.Reader) ([]*ProcessEntry, error) {
	processes := []*ProcessEntry{}
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		m := UNIX_PS_REGEX.FindStringSubmatch(line)
		if len(m) != 11 {
			return nil, &ErrorParsingPs{Line: line}
		}
		if m[1] == "PID" {
			// header
			continue
		}

		pid, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			log.Error().Err(err).Msg("cannot parse unix pid " + m[1])
			continue
		}
		uid, err := strconv.ParseInt(m[9], 10, 64)
		if err != nil {
			log.Error().Err(err).Msg("cannot parse unix uid " + m[9])
			continue
		}

		// PID %CPU %MEM    VSZ   RSS TTY       STAT  TIME   UID COMMAND
		p := &ProcessEntry{
			Pid:     pid,
			CPU:     m[2],
			Mem:     m[3],
			Vsz:     m[4],
			Rss:     m[5],
			Tty:     m[6],
			Stat:    m[7],
			Time:    m[8],
			Uid:     uid,
			Command: m[10],
		}
		processes = append(processes, p)
	}

	return processes, nil
}

func ParseAixPsResult(input io.Reader) ([]*ProcessEntry, error) {
	processes := []*ProcessEntry{}
	re := AIX_PS_REGEX
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		// skip zombies, which AIX prints as <defunct> with their other
		// columns blank
		if strings.Contains(line, "<defunct>") {
			continue
		}

		// The header says whether the state column (S) was asked for.
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == "PID" {
			if slices.Contains(fields, "S") {
				re = AIX_PS_STATE_REGEX
			}
			continue
		}

		m := re.FindStringSubmatch(line)
		if m == nil {
			if strings.Contains(line, "<idle>") || strings.Contains(line, "<kproc>") {
				// skip idle and kernel processes
				continue
			}
			return nil, &ErrorParsingPs{Line: line}
		}

		pid, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			log.Error().Err(err).Msg("cannot parse unix pid " + m[1])
			continue
		}
		uid, err := strconv.ParseInt(m[7], 10, 64)
		if err != nil {
			log.Error().Err(err).Msg("cannot parse unix uid " + m[7])
			continue
		}

		// PID  %CPU  %MEM   VSZ     TT        TIME UID [S] COMMAND
		p := &ProcessEntry{
			Pid:     pid,
			CPU:     m[2],
			Mem:     m[3],
			Vsz:     m[4],
			Tty:     m[5],
			Time:    m[6],
			Uid:     uid,
			Command: m[len(m)-1],
		}
		if len(m) == 10 {
			p.Stat = m[8]
		}
		processes = append(processes, p)
	}

	return processes, nil
}

type UnixProcessManager struct {
	conn     shared.Connection
	platform *inventory.Platform

	// The process list is fetched via a single `ps` invocation and memoized.
	// Exists() and Process() consult the cached list/map instead of re-running
	// `ps`, which avoids ~2N `ps` commands when resolving N process(pid:) lookups
	// over slow connections (e.g. SSH).
	lock      sync.Mutex
	loaded    bool
	processes []*OSProcess
	byPid     map[int64]*OSProcess
}

func (upm *UnixProcessManager) Name() string {
	return "Unix Process Manager"
}

// List returns all running processes. The underlying `ps` command runs only
// once per manager; subsequent calls (including via Exists/Process) return the
// memoized result.
func (upm *UnixProcessManager) List() ([]*OSProcess, error) {
	upm.lock.Lock()
	defer upm.lock.Unlock()
	return upm.listLocked()
}

// listLocked returns the memoized process list, running `ps` on first use.
// Callers must hold upm.lock.
func (upm *UnixProcessManager) listLocked() ([]*OSProcess, error) {
	if upm.loaded {
		return upm.processes, nil
	}

	ps, err := upm.runList()
	if err != nil {
		// Don't memoize transient failures (SSH timeout, rate limit, ...);
		// leaving upm.loaded false lets a later call retry the ps command.
		return nil, err
	}
	upm.processes = ps
	upm.byPid = make(map[int64]*OSProcess, len(ps))
	for i := range ps {
		// preserve first-match semantics if duplicate pids ever appear
		if _, ok := upm.byPid[ps[i].Pid]; !ok {
			upm.byPid[ps[i].Pid] = ps[i]
		}
	}
	upm.loaded = true

	return upm.processes, nil
}

// runPs runs a ps invocation and fails loudly when it does not succeed. ps
// writes nothing to stdout when it rejects its arguments, which would otherwise
// parse into an empty slice and report a running host as having no processes.
func (upm *UnixProcessManager) runPs(command string) (io.Reader, error) {
	c, err := upm.conn.RunCommand(command)
	if err != nil {
		// wrapped so a caller can tell a dead connection from a ps that ran
		return nil, fmt.Errorf("processes> could not run %q: %w", command, err)
	}
	if c.ExitStatus != 0 {
		stderr, _ := io.ReadAll(c.Stderr)
		return nil, fmt.Errorf("processes> %q failed with exit code %d: %s",
			command, c.ExitStatus, strings.TrimSpace(string(stderr)))
	}
	return c.Stdout, nil
}

// runList runs the platform-appropriate `ps` command and parses its output.
func (upm *UnixProcessManager) runList() ([]*OSProcess, error) {
	var entries []*ProcessEntry
	// NOTE: improve proc parser instead of supporting multiple ps commands
	switch {
	case upm.platform.Name == "solaris":
		// Solaris ships an SVR4 ps that rejects the BSD-style "axo" cluster with
		// "ps: illegal option -- o", and has no /usr/ucb/ps to fall back on. This
		// has to be tested before the linux family, because Solaris 11.4 ships an
		// /etc/os-release and is therefore reported as part of it.
		stdout, err := upm.runPs("ps -eo pid,pcpu,pmem,vsz,rss,tty,s,time,uid,args")
		if err != nil {
			return nil, err
		}

		entries, err = ParseUnixPsResult(stdout)
		if err != nil {
			return nil, err
		}
	case upm.platform.IsFamily("linux"):
		stdout, err := upm.runPs("ps axo pid,pcpu,pmem,vsz,rss,tty,stat,stime,time,uid,command")
		if err != nil {
			return nil, err
		}

		entries, err = ParseLinuxPsResult(stdout)
		if err != nil {
			return nil, err
		}
	case upm.platform.IsFamily("darwin"):
		// NOTE: special case on darwin is that the ps axo only shows processes for users with terminals
		// TODO: the same applies to OpenBSD and may result in missing processes
		stdout, err := upm.runPs("ps Axo pid,pcpu,pmem,vsz,rss,tty,stat,stime,time,uid,command")
		if err != nil {
			return nil, err
		}

		entries, err = ParseLinuxPsResult(stdout)
		if err != nil {
			return nil, err
		}
	case upm.platform.Name == "aix":
		// special case for aix since it does not understand x
		stdout, err := upm.runPs("ps -A -o pid,pcpu,pmem,vsz,tty,time,uid,state,args")
		if err != nil {
			return nil, err
		}

		entries, err = ParseAixPsResult(stdout)
		if err != nil {
			return nil, err
		}
	default:
		// TODO: consider using different ps calls for different platforms to determine max information
		// do not use stime since it is not available on FreeBSD
		stdout, err := upm.runPs("ps axo pid,pcpu,pmem,vsz,rss,tty,stat,time,uid,command")
		if err != nil {
			return nil, err
		}

		entries, err = ParseUnixPsResult(stdout)
		if err != nil {
			return nil, err
		}
	}

	log.Debug().Int("processes", len(entries)).Msg("found processes")

	isFreeBSD := upm.platform.Name == "freebsd"
	isSolaris := upm.platform.Name == "solaris"
	isAix := upm.platform.Name == "aix"
	var comms map[int64]string
	if isFreeBSD {
		comms = upm.freebsdComms()
	}
	var ps []*OSProcess
	for i := range entries {
		p := entries[i].ToOSProcess()
		if isSolaris {
			p.State = solarisProcessState(entries[i].Stat)
		}
		if isAix {
			p.State = aixProcessState(entries[i].Stat)
		}
		if isFreeBSD {
			p.State = freebsdProcessState(entries[i].Stat)
			if comm, ok := comms[p.Pid]; ok {
				p.Executable = comm
			}
		}
		ps = append(ps, p)
	}
	return ps, nil
}

// freebsdComms returns the name of the binary each process exec'd, keyed by
// pid, from ps's comm column. FreeBSD daemons rewrite their process title with
// setproctitle(3) ("nginx: master process ...", "sshd: /usr/sbin/sshd
// [listener] ...", "(postgres)"), so the first word of the command column does
// not name the binary. comm is the exec'd file name (up to MAXCOMLEN
// characters), the counterpart of the Name line in Linux's /proc/<pid>/status.
// It runs as a separate ps call because a comm can contain spaces (kernel
// threads such as "sequencer 00"), which only parses as the last column. A
// failure leaves the map empty, and every process keeps the executable taken
// from its command.
func (upm *UnixProcessManager) freebsdComms() map[int64]string {
	stdout, err := upm.runPs("ps ax -o pid= -o comm=")
	if err != nil {
		log.Debug().Err(err).Msg("processes> could not read process names, using the command")
		return nil
	}
	return ParseFreeBSDComms(stdout)
}

// ParseFreeBSDComms parses the output of `ps ax -o pid= -o comm=`: a pid, then
// the rest of the line as the name.
func ParseFreeBSDComms(input io.Reader) map[int64]string {
	res := map[int64]string{}
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		pidStr, comm, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		pid, err := strconv.ParseInt(pidStr, 10, 64)
		if err != nil {
			continue
		}
		if comm = strings.TrimSpace(comm); comm != "" {
			res[pid] = comm
		}
	}
	return res
}

// freebsdRunStates names the run state that leads a FreeBSD ps STAT column,
// as documented in ps(1). The labels follow the Linux /proc/<pid>/status
// wording where the meaning is the same (R, S, D, T, Z, I).
var freebsdRunStates = map[byte]string{
	'D': "disk sleep",       // disk or other short-term uninterruptible wait
	'I': "idle",             // sleeping for longer than about 20 seconds
	'L': "lock wait",        // waiting to acquire a lock
	'R': "running",          // runnable
	'S': "sleeping",         // sleeping for less than about 20 seconds
	'T': "stopped",          // stopped
	'W': "interrupt thread", // idle interrupt thread
	'Z': "zombie",           // dead, not yet reaped
}

// freebsdProcessState turns a FreeBSD ps STAT value such as "SLs" or "RNL"
// into the "<letter> (<name>)" form Linux reports, for example "S (sleeping)".
// Only the first character is the run state; the rest are modifiers (session
// leader, locked pages, niceness) that Linux does not report either. An
// undocumented letter is kept as is, and an empty value stays empty.
func freebsdProcessState(stat string) string {
	if stat == "" {
		return ""
	}
	if name, ok := freebsdRunStates[stat[0]]; ok {
		return stat[:1] + " (" + name + ")"
	}
	return stat[:1]
}

// aixRunStates names the state letter of AIX ps -o state, as documented in
// ps(1). AIX reports a runnable and a sleeping process alike as active.
var aixRunStates = map[byte]string{
	'A': "active",      // running, runnable or sleeping
	'I': "idle",        // being created
	'O': "nonexistent", // its process table slot is free
	'T': "stopped",     // stopped by a signal or traced
	'W': "swapped",     // swapped out
	'Z': "zombie",      // dead, not yet reaped
}

// aixProcessState turns the AIX ps state letter into the "<letter> (<name>)"
// form Linux reports, for example "A (active)". An undocumented letter is
// kept as is, and an empty value stays empty.
func aixProcessState(stat string) string {
	if stat == "" {
		return ""
	}
	if name, ok := aixRunStates[stat[0]]; ok {
		return stat[:1] + " (" + name + ")"
	}
	return stat[:1]
}

// solarisRunStates names the one-letter state of the SVR4 ps `s` column on
// Solaris, as documented in ps(1). The labels follow the Linux
// /proc/<pid>/status wording where the meaning is the same.
var solarisRunStates = map[byte]string{
	'O': "running",      // on a processor
	'R': "runnable",     // on a run queue
	'S': "sleeping",     // waiting for an event
	'T': "stopped",      // stopped by a job control signal or traced
	'W': "cpu cap wait", // waiting for CPU usage to drop below its cap
	'Z': "zombie",       // dead, not yet reaped
}

// solarisProcessState turns the Solaris ps state letter into the
// "<letter> (<name>)" form Linux reports, for example "S (sleeping)". An
// undocumented letter is kept as is, and an empty value stays empty.
func solarisProcessState(stat string) string {
	if stat == "" {
		return ""
	}
	if name, ok := solarisRunStates[stat[0]]; ok {
		return stat[:1] + " (" + name + ")"
	}
	return stat[:1]
}

// ListSocketInodesByProcess returns a map with a pid as key and a list of socket inodes as value
func (upm *UnixProcessManager) ListSocketInodesByProcess() (map[int64]plugin.TValue[[]int64], error) {
	startTime := time.Now()
	// Use -lname to filter for socket symlinks at the kernel level and -printf to
	// avoid spawning a child process per FD. This is orders of magnitude faster
	// than the previous `find -exec ls -n {} \;` on systems with many open FDs.
	// Note: -lname and -printf are GNU find extensions. This is safe because
	// UnixProcessManager only calls this on Linux targets (via SSH), which always
	// have GNU find. On macOS/FreeBSD, /proc doesn't exist so the command is a no-op.
	// Output format: "<fd> socket:[<inode>] /proc/<pid>/fd"
	c, err := upm.conn.RunCommand("find /proc/[0-9]*/fd -maxdepth 1 -lname 'socket:*' -printf '%f %l %h\\n' 2>/dev/null")
	if err != nil {
		return nil, fmt.Errorf("processes> could not run command: %v", err)
	}

	processesInodesByPid := map[int64]plugin.TValue[[]int64]{}
	scanner := bufio.NewScanner(c.Stdout)
	for scanner.Scan() {
		line := scanner.Text()
		pid, inode, err := ParseFindSocketLine(line)
		if err != nil || (pid == 0 && inode == 0) {
			pluginValue := processesInodesByPid[pid]
			pluginValue.Error = err
			processesInodesByPid[pid] = pluginValue
			continue
		}
		pluginValue := plugin.TValue[[]int64]{}
		if _, ok := processesInodesByPid[pid]; ok {
			pluginValue = processesInodesByPid[pid]
			pluginValue.Data = append(pluginValue.Data, inode)
		} else {
			pluginValue.Data = []int64{inode}
		}
		processesInodesByPid[pid] = pluginValue
	}
	log.Debug().Int64("duration (ms)", time.Duration(time.Since(startTime)).Milliseconds()).Msg("parsing find for process socket inodes")

	return processesInodesByPid, nil
}

func (upm *UnixProcessManager) Exists(pid int64) (bool, error) {
	upm.lock.Lock()
	defer upm.lock.Unlock()

	if _, err := upm.listLocked(); err != nil {
		return false, err
	}

	_, ok := upm.byPid[pid]
	return ok, nil
}

// Process returns the process for the given pid. A pid that is not in the
// process list is reported as an error, matching the linux, docker and windows
// managers: callers check err and then dereference, so a (nil, nil) not-found
// result panicked them instead.
func (upm *UnixProcessManager) Process(pid int64) (*OSProcess, error) {
	upm.lock.Lock()
	defer upm.lock.Unlock()

	if _, err := upm.listLocked(); err != nil {
		return nil, err
	}

	process, ok := upm.byPid[pid]
	if !ok {
		return nil, fmt.Errorf("process %d does not exist", pid)
	}

	return process, nil
}

// reFindSocketPrintf parses the output of:
//
//	find /proc/[0-9]*/fd -maxdepth 1 -lname 'socket:*' -printf '%f %l %h\n'
//
// Example line: "3 socket:[41866685] /proc/1/fd"
var reFindSocketPrintf = regexp.MustCompile(
	`^\d+\s+socket:\[(\d+)\]\s+/proc/(\d+)/fd$`,
)

// ParseFindSocketLine parses a single line of the -printf based find output.
func ParseFindSocketLine(line string) (int64, int64, error) {
	m := reFindSocketPrintf.FindStringSubmatch(line)
	if len(m) == 0 {
		return 0, 0, nil
	}

	inode, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		log.Error().Err(err).Msg("cannot parse socket inode " + m[1])
		return 0, 0, err
	}

	pid, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil {
		log.Error().Err(err).Msg("cannot parse unix pid " + m[2])
		return 0, 0, err
	}

	return pid, inode, nil
}

func ParseLinuxFindLine(line string) (int64, int64, error) {
	if strings.HasSuffix(line, "Permission denied") || strings.HasSuffix(line, "No such file or directory") {
		return 0, 0, nil
	}

	m := reFindSockets.FindStringSubmatch(line)
	if len(m) == 0 {
		return 0, 0, nil
	}

	pid, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		log.Error().Err(err).Msg("cannot parse unix pid " + m[1])
		return 0, 0, err
	}

	inode, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil {
		log.Error().Err(err).Msg("cannot parse socket inode " + m[2])
		return 0, 0, err
	}

	return pid, inode, nil
}

type ErrorParsingPs struct {
	Line string
}

func (e *ErrorParsingPs) Error() string {
	return fmt.Sprintf("error parsing ps output: %s", e.Line)
}

func (e *ErrorParsingPs) Is(target error) bool {
	if _, ok := target.(*ErrorParsingPs); ok {
		return true
	}
	return false
}
