// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package serverlaunch works out how a server was started: the command line
// and environment of its running master process, read from /proc, or of the
// process a container image starts. A server reads its command line and
// environment after its configuration file, so whatever they set wins over
// the file.
package serverlaunch

import (
	"path"
	"slices"
	"strconv"
	"strings"
)

// Process is one process as /proc shows it.
type Process struct {
	Pid  int
	PPid int
	// Argv is the command line, argv[0] included.
	Argv []string
}

// SplitCmdline splits the NUL-separated content of /proc/<pid>/cmdline.
func SplitCmdline(data []byte) []string {
	s := strings.TrimRight(string(data), "\x00")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

// PsCommand lists every process with its parent and command line, for a
// system whose /proc has no command lines: AIX keeps the System V layout
// (psinfo, status) and has no pgrep.
const PsCommand = "ps -A -o pid= -o ppid= -o args="

// ParsePs reads the output of PsCommand. ps joins the arguments with
// spaces, so an argument that holds a space is split in two; the program and
// the options a server is recognized by are not affected.
func ParsePs(out string) []Process {
	var procs []Process
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		procs = append(procs, Process{Pid: pid, PPid: ppid, Argv: fields[2:]})
	}
	return procs
}

// ParseStatPPid returns the parent pid from the content of /proc/<pid>/stat.
// The second field, the program name in parentheses, may itself hold spaces
// and parentheses, so the fields are counted from the last ")".
func ParseStatPPid(stat []byte) (int, bool) {
	s := string(stat)
	end := strings.LastIndexByte(s, ')')
	if end < 0 {
		return 0, false
	}
	// after ")" come the state and then the parent pid
	fields := strings.Fields(s[end+1:])
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, false
	}
	return ppid, true
}

// ParseEnviron splits the NUL-separated content of /proc/<pid>/environ into
// variables. An entry without "=" is skipped; a variable set twice keeps the
// first value, which is the one getenv(3) returns.
func ParseEnviron(data []byte) map[string]string {
	return EnvList(strings.Split(string(data), "\x00"))
}

// EnvList turns a list of NAME=value entries, as in an image configuration's
// Env, into variables. An entry without "=" is skipped; a variable set twice
// keeps the first value.
func EnvList(entries []string) map[string]string {
	env := map[string]string{}
	for _, e := range entries {
		k, v, ok := strings.Cut(e, "=")
		if !ok || k == "" {
			continue
		}
		if _, seen := env[k]; !seen {
			env[k] = v
		}
	}
	return env
}

// Masters returns the processes that run the server and were not started by
// another process of the server, lowest pid first. A server's workers (httpd
// children, haproxy's worker under -W, postgres backends) run with the
// master's command line or a rewritten one, and the master's is the one that
// says how the server was started. isServer reports whether a command line
// starts the server.
func Masters(procs []Process, isServer func(argv []string) bool) []Process {
	servers := map[int]bool{}
	var candidates []Process
	for _, p := range procs {
		if len(p.Argv) == 0 || !isServer(p.Argv) {
			continue
		}
		servers[p.Pid] = true
		candidates = append(candidates, p)
	}
	var out []Process
	for _, p := range candidates {
		if p.PPid != p.Pid && servers[p.PPid] {
			continue
		}
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b Process) int { return a.Pid - b.Pid })
	return out
}

// ImageArgv returns the server command line a container image starts:
// its Entrypoint followed by its Cmd, from the first argument isServer
// accepts. Official images start most servers through a wrapper
// (docker-entrypoint.sh haproxy -f ..., httpd-foreground), so the wrapper
// is skipped. A Cmd that starts with an option instead of a program, behind
// an entrypoint script, is the convention for passing options to the image's
// server (ubuntu/squid: entrypoint.sh -f /etc/squid/squid.conf -NYC); it is
// returned behind defaultName. It returns nil when the image does not start
// the server.
func ImageArgv(entrypoint, cmd []string, isServer func(argv []string) bool, defaultName string) []string {
	all := make([]string, 0, len(entrypoint)+len(cmd))
	all = append(all, entrypoint...)
	all = append(all, cmd...)
	for i := range all {
		if isServer(all[i:]) {
			return slices.Clone(all[i:])
		}
	}
	if defaultName == "" || len(entrypoint) == 0 || len(cmd) == 0 || !strings.HasPrefix(cmd[0], "-") {
		return nil
	}
	if !strings.Contains(path.Base(entrypoint[len(entrypoint)-1]), "entrypoint") {
		return nil
	}
	return append([]string{defaultName}, cmd...)
}

// IsProgram returns an isServer for Masters and ImageArgv that accepts a
// command line whose program's base name is one of names.
func IsProgram(names ...string) func(argv []string) bool {
	return func(argv []string) bool {
		return len(argv) > 0 && slices.Contains(names, path.Base(argv[0]))
	}
}
