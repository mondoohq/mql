// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"errors"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// Binary is a tool executable found on the target.
type Binary struct {
	// Path is where the binary was found, as FindBinary reports it.
	Path string
	// Target is Path with every symbolic link resolved. Empty when the
	// resolution failed.
	Target string
	// Trusted reports whether the scan may execute the binary: see
	// trustedResolution.
	Trusted bool
}

// LocateBinary finds binaryName like FindBinary does and checks whether the
// scan may execute it. ok is false when the binary is not found.
func LocateBinary(conn shared.Connection, binaryName string) (Binary, bool) {
	p := FindBinary(conn, binaryName)
	if p == "" {
		return Binary{}, false
	}
	target, trusted := ResolveTrustedExecutable(conn, p)
	return Binary{Path: p, Target: target, Trusted: trusted}, true
}

// ResolveTrustedExecutable resolves every symbolic link in the absolute path p
// on the target and reports whether the scan may execute it. A binary is
// trusted when the file and every directory that the path resolution walks
// through, links included, are owned by root or by the account the scan runs
// commands as, and none of them is writable by group or others. Anything else
// can be replaced by another account: a root scan running it would hand that
// account code execution as root. This is the case for a Node tarball
// unpacked as root, which keeps the archive's uid 1000 on
// /usr/local/lib/node_modules, and for Homebrew's /opt/homebrew/bin, which
// belongs to the user who installed it. A script is trusted only when the
// interpreter its #! line names, and the one env finds on the PATH for
// `#!/usr/bin/env <name>`, pass the same check (see trustedExecutable): the
// kernel runs that interpreter with the scan's privileges.
//
// target is the resolved path, empty when the resolution failed, which is
// also untrusted.
func ResolveTrustedExecutable(conn shared.Connection, p string) (target string, trusted bool) {
	if !strings.HasPrefix(p, "/") || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return "", false
	}
	uid, ok := commandUID(conn)
	if !ok {
		return "", false
	}
	lstat := func(paths []string) map[string]pathEntry {
		cmd, err := conn.RunCommand("LC_ALL=C ls -ldn -- " + shellQuoteAll(paths))
		if err != nil {
			return nil
		}
		// ls exits non-zero when one operand is missing and still lists the
		// others, so the output is parsed whatever the exit status.
		return parseLsLong(readCommandOutput(cmd.Stdout), paths)
	}
	x := execProbe{
		uid:   uid,
		lstat: lstat,
		head: func(p string) ([]byte, error) {
			f, err := conn.FileSystem().Open(p)
			if err != nil {
				return nil, errors.New("cannot read " + p)
			}
			defer f.Close()
			b, err := io.ReadAll(io.LimitReader(f, shebangLen))
			if err != nil {
				return nil, errors.New("cannot read " + p)
			}
			return b, nil
		},
		path: func() (string, bool) { return commandPath(conn) },
	}
	target, err := trustedExecutable(p, x, 0)
	if err != "" {
		log.Debug().Str("path", p).Str("reason", err).
			Msg("mql[packages]> not executing a binary another account can replace")
		return target, false
	}
	return target, true
}

// commandUIDs caches commandUID per connection id: the account commands run
// as does not change for the life of a connection.
var commandUIDs sync.Map // uint32 -> int64

// commandUID returns the uid that commands run as on the target: root for a
// root or sudo scan.
func commandUID(conn shared.Connection) (int64, bool) {
	if uid, ok := commandUIDs.Load(conn.ID()); ok {
		return uid.(int64), true
	}
	cmd, err := conn.RunCommand("id -u")
	if err != nil || cmd.ExitStatus != 0 {
		return 0, false
	}
	uid, err := strconv.ParseInt(strings.TrimSpace(readCommandOutput(cmd.Stdout)), 10, 64)
	if err != nil {
		return 0, false
	}
	commandUIDs.Store(conn.ID(), uid)
	return uid, true
}

// commandPaths caches commandPath per connection id.
var commandPaths sync.Map // uint32 -> string

// commandPath returns the PATH that commands run with on the target, which
// for a sudo scan is sudo's secure_path. false when it is unknown.
func commandPath(conn shared.Connection) (string, bool) {
	if p, ok := commandPaths.Load(conn.ID()); ok {
		return p.(string), true
	}
	cmd, err := conn.RunCommand("printenv PATH")
	if err != nil || cmd.ExitStatus != 0 {
		return "", false
	}
	p := strings.TrimRight(readCommandOutput(cmd.Stdout), "\r\n")
	if p == "" {
		return "", false
	}
	commandPaths.Store(conn.ID(), p)
	return p, true
}

// pathEntry is what `ls -ldn` reports for one path, without following it.
type pathEntry struct {
	mode string // the 10-character mode, e.g. "drwxr-xr-x"
	uid  int64
	link string // the link's target, for a symbolic link
}

func (e pathEntry) isLink() bool { return strings.HasPrefix(e.mode, "l") }
func (e pathEntry) isDir() bool  { return strings.HasPrefix(e.mode, "d") }

// executable reports whether anyone may execute the entry.
func (e pathEntry) executable() bool {
	return len(e.mode) >= 10 && strings.ContainsAny(e.mode[3:4]+e.mode[6:7]+e.mode[9:10], "xst")
}

// writableByOthers reports whether group or others may write to the entry.
func (e pathEntry) writableByOthers() bool {
	return len(e.mode) >= 10 && (e.mode[5] == 'w' || e.mode[8] == 'w')
}

// lsLongLine splits an `LC_ALL=C ls -ldn` line into mode, uid and the name
// (plus " -> target" for a link). The date takes three fields in the C locale.
var lsLongLine = regexp.MustCompile(`^(\S{10})\S*\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\S+\s+\S+\s+\S+ (.+)$`)

// parseLsLong reads `LC_ALL=C ls -ldn` output for paths, keyed by path as it
// was passed. A link line reads "<path> -> <target>"; the path is matched
// against the ones passed, so a " -> " inside a name or a target does not
// split it in the wrong place.
func parseLsLong(out string, paths []string) map[string]pathEntry {
	entries := map[string]pathEntry{}
	for _, line := range strings.Split(out, "\n") {
		m := lsLongLine.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		uid, err := strconv.ParseInt(m[2], 10, 64)
		if err != nil {
			continue
		}
		e := pathEntry{mode: m[1], uid: uid}
		name := m[3]
		if e.isLink() {
			n, target, found := splitLsLink(name, paths)
			if !found {
				continue
			}
			name, e.link = n, target
		}
		entries[name] = e
	}
	return entries
}

// splitLsLink splits "<path> -> <target>" at the longest of paths it starts
// with, and at the first " -> " when it starts with none of them.
func splitLsLink(name string, paths []string) (string, string, bool) {
	best := ""
	for _, p := range paths {
		if len(p) > len(best) && strings.HasPrefix(name, p+" -> ") {
			best = p
		}
	}
	if best != "" {
		return best, name[len(best)+len(" -> "):], true
	}
	return strings.Cut(name, " -> ")
}

// maxLinkHops bounds the symbolic links followed, like the kernel's ELOOP.
const maxLinkHops = 40

// trustedResolution resolves p one component at a time, the way the kernel
// does when it executes p, and checks every directory it walks through and
// the file it ends at: each must be owned by root or by uid and must not be
// writable by group or others. Links are not checked themselves (a link
// cannot be changed in place, only replaced by whoever may write to its
// directory, which was checked), but the walk restarts at their target.
// lstat reports paths without following them; it is called with every prefix
// of the path being walked at once, so a resolution costs one call per link.
// It returns the resolved path, and the reason it is untrusted (empty when it
// is trusted). An untrusted component does not stop the walk, so the resolved
// path is still known for reading files next to the binary; a component that
// cannot be read does, and the resolved path is then empty.
func trustedResolution(p string, uid int64, lstat func([]string) map[string]pathEntry) (string, string) {
	target, reason, _ := resolveTrusted(p, uid, lstat, false)
	return target, reason
}

// resolveTrusted is trustedResolution for a file (wantDir false) or a
// directory (wantDir true). missing reports that a component does not exist
// while every component before it is trusted: nobody but root or uid can
// create it then.
func resolveTrusted(p string, uid int64, lstat func([]string) map[string]pathEntry, wantDir bool) (target, reason string, missing bool) {
	trusted := func(e pathEntry) bool {
		return (e.uid == 0 || e.uid == uid) && !e.writableByOthers()
	}

	hops := 0
	cur := path.Clean(p)
	for {
		prefixes := pathPrefixes(cur)
		entries := lstat(prefixes)
		restarted := false
		for i, prefix := range prefixes {
			e, ok := entries[prefix]
			if !ok {
				if reason != "" {
					return "", reason, false
				}
				return "", prefix + " cannot be read", true
			}
			if e.isLink() {
				hops++
				if hops > maxLinkHops {
					return "", "too many symbolic links at " + prefix, false
				}
				target := e.link
				if !strings.HasPrefix(target, "/") {
					target = path.Join(path.Dir(prefix), target)
				}
				rest := strings.TrimPrefix(cur, prefix)
				cur = path.Clean(target + rest)
				restarted = true
				break
			}
			if !trusted(e) && reason == "" {
				reason = prefix + " is owned by uid " + strconv.FormatInt(e.uid, 10) + " with mode " + e.mode
			}
			last := i == len(prefixes)-1
			if !last && !e.isDir() {
				return "", prefix + " is not a directory", false
			}
			if last && e.isDir() != wantDir {
				if wantDir {
					return "", prefix + " is not a directory", false
				}
				return "", prefix + " is a directory", false
			}
		}
		if !restarted {
			return cur, reason, false
		}
	}
}

// execProbe is what trustedExecutable reads from the target.
type execProbe struct {
	// uid is the account commands run as.
	uid int64
	// lstat reports paths without following them (see trustedResolution).
	lstat func([]string) map[string]pathEntry
	// head returns the first bytes of a file.
	head func(path string) ([]byte, error)
	// path returns the PATH commands run with, false when it is unknown.
	path func() (string, bool)
}

// maxInterpreterDepth is how many scripts trustedExecutable follows from a
// script to the interpreter that runs it, a binary at the end. Linux follows
// a few more; a chain this long does not occur in practice and is refused.
const maxInterpreterDepth = 4

// shebangLen is how much of a file the kernel reads for its #! line.
const shebangLen = 256

// trustedExecutable is trustedResolution for a file the scan is about to
// execute, followed through the interpreters the kernel runs for it: a
// script's #! interpreter is executed with the script's privileges, so it is
// checked the same way, and so is the one it names in turn. For
// `#!/usr/bin/env <name>`, env looks <name> up on the PATH, so every PATH
// directory up to the one that holds it must pass the check as well: one
// another account can write to lets that account put its own <name> first.
// depth counts the scripts followed so far.
func trustedExecutable(p string, x execProbe, depth int) (string, string) {
	target, reason := trustedResolution(p, x.uid, x.lstat)
	if reason != "" {
		return target, reason
	}
	head, err := x.head(target)
	if err != nil {
		// root reads every file, so a file root cannot read is refused. An
		// unprivileged account cannot read some binaries it may execute
		// (RHEL ships sudo as mode 4111); whatever such a file starts, it
		// starts with that account's privileges, which are the scan's own.
		if x.uid != 0 {
			return target, ""
		}
		return target, err.Error()
	}
	interp, arg, ok := parseShebang(head)
	if !ok {
		return target, ""
	}
	if depth >= maxInterpreterDepth {
		return target, "interpreters nest deeper than the kernel follows"
	}
	if interp == "" {
		return target, "the file names no interpreter"
	}
	if !strings.HasPrefix(interp, "/") {
		return target, "interpreter " + interp + " is not absolute"
	}
	interpTarget, r := trustedExecutable(interp, x, depth+1)
	if r != "" {
		return target, "interpreter " + interp + ": " + r
	}
	// env is recognized by the name the #! line gives it, which is what a
	// multi-call binary such as busybox goes by, or by the file it resolves
	// to, so a link with another name to env is followed too. A copy of env
	// under another name is not recognized.
	if path.Base(interp) != "env" && path.Base(interpTarget) != "env" {
		return target, ""
	}

	prog, r := envProgram(arg)
	if r != "" {
		return target, r
	}
	if strings.Contains(prog, "/") {
		if !strings.HasPrefix(prog, "/") {
			return target, "interpreter " + prog + " is not absolute"
		}
		if _, r := trustedExecutable(prog, x, depth+1); r != "" {
			return target, "interpreter " + prog + ": " + r
		}
		return target, ""
	}
	if r := trustedPathLookup(prog, x, depth+1); r != "" {
		return target, "interpreter " + prog + ": " + r
	}
	return target, ""
}

// trustedPathLookup checks the program env runs for name: it walks the PATH
// in order, like env does, and every directory up to the one that holds an
// executable name must pass the check, then that file must.
func trustedPathLookup(name string, x execProbe, depth int) string {
	pathEnv, ok := x.path()
	if !ok {
		return "the PATH commands run with is unknown"
	}
	for _, dir := range strings.Split(pathEnv, ":") {
		if !strings.HasPrefix(dir, "/") {
			// an empty entry is the working directory
			return "PATH entry " + dir + " is not absolute"
		}
		resolved, reason, missing := resolveTrusted(dir, x.uid, x.lstat, true)
		if missing {
			continue
		}
		if reason != "" {
			return "PATH entry " + dir + ": " + reason
		}
		candidate := path.Join(resolved, name)
		e, found := x.lstat([]string{candidate})[candidate]
		if !found || e.isDir() || (!e.isLink() && !e.executable()) {
			continue
		}
		if _, r := trustedExecutable(candidate, x, depth); r != "" {
			return r
		}
		return ""
	}
	return name + " is not found on PATH"
}

// parseShebang splits a file's #! line the way Linux does: the interpreter
// runs up to the first blank, and the rest of the line, trimmed, is one
// argument. ok is false when the file does not start with #!.
func parseShebang(head []byte) (interp, arg string, ok bool) {
	if len(head) < 2 || head[0] != '#' || head[1] != '!' {
		return "", "", false
	}
	line := string(head[2:])
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = strings.Trim(line, " \t")
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		return line[:i], strings.Trim(line[i+1:], " \t"), true
	}
	return line, "", true
}

// envProgram returns the program `env <arg>` runs, or why it cannot tell.
// Linux hands the rest of the #! line to env as one argument and macOS splits
// it; splitting it here finds the program either way. Variable assignments
// are skipped, but one to PATH changes where env looks, and an option other
// than -S may change it too, so both are refused.
func envProgram(arg string) (string, string) {
	for _, f := range strings.Fields(arg) {
		switch {
		case f == "-S" || f == "--split-string":
			continue
		case strings.HasPrefix(f, "-"):
			return "", "env option " + f + " is not understood"
		case strings.HasPrefix(f, "PATH="):
			return "", "env changes PATH"
		case strings.Contains(f, "="):
			continue
		default:
			return f, ""
		}
	}
	return "", "env names no program"
}

// pathPrefixes returns "/" and every prefix of the clean absolute path p, p
// itself last: "/usr/bin/x" gives "/", "/usr", "/usr/bin", "/usr/bin/x".
func pathPrefixes(p string) []string {
	out := []string{"/"}
	if p == "/" {
		return out
	}
	for i := 1; i < len(p); i++ {
		if p[i] == '/' {
			out = append(out, p[:i])
		}
	}
	return append(out, p)
}

// shellQuoteAll single-quotes each path and joins them with spaces.
func shellQuoteAll(paths []string) string {
	quoted := make([]string, len(paths))
	for i, p := range paths {
		quoted[i] = shellQuote(p)
	}
	return strings.Join(quoted, " ")
}
