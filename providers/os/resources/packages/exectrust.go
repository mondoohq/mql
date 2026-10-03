// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	lstat := func(paths []string) lsResult {
		cmd, err := conn.RunCommand("LC_ALL=C ls -ldn -- " + shellQuoteAll(paths))
		if err != nil {
			return lsResult{}
		}
		// ls exits non-zero when one operand is missing and still lists the
		// others, so the output is parsed whatever the exit status.
		return parseLs(readCommandOutput(cmd.Stdout), readCommandOutput(cmd.Stderr), paths)
	}
	x := execProbe{
		uid:   uid,
		lstat: lstat,
		head: func(p string) ([]byte, error) {
			f, err := conn.FileSystem().Open(p)
			if err != nil {
				return nil, fmt.Errorf("cannot read %s: %w", p, err)
			}
			defer f.Close()
			b, err := io.ReadAll(io.LimitReader(f, shebangLen))
			if err != nil {
				return nil, fmt.Errorf("cannot read %s: %w", p, err)
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
	size int64
	link string // the link's target, for a symbolic link
}

// lsResult is what one `ls -ldn` call reports for the paths it was given.
// A path in neither map could not be listed: ls failed, did not run, or
// printed something that is not understood. That is not the same as absent.
type lsResult struct {
	entries map[string]pathEntry
	// absent holds the paths ls reported as not existing.
	absent map[string]bool
}

// parseLs reads the stdout and stderr of `LC_ALL=C ls -ldn` for paths.
func parseLs(stdout, stderr string, paths []string) lsResult {
	return lsResult{entries: parseLsLong(stdout, paths), absent: parseLsAbsent(stderr, paths)}
}

// parseLsAbsent returns the paths that ls reported as not existing, from
// lines such as GNU's "ls: cannot access '/x': No such file or directory"
// (in double quotes for a name holding a single quote, unquoted before
// coreutils 8.25), and busybox's and macOS's "ls: /x: No such file or
// directory". A path whose name ls escapes in any other way is not matched,
// and so reads as unlisted rather than absent.
func parseLsAbsent(stderr string, paths []string) map[string]bool {
	absent := map[string]bool{}
	for _, line := range strings.Split(stderr, "\n") {
		body, ok := strings.CutSuffix(strings.TrimRight(line, "\r"), ": No such file or directory")
		if !ok {
			continue
		}
		for _, p := range paths {
			switch body {
			case "ls: " + p, "ls: cannot access " + p, "ls: cannot access '" + p + "'", `ls: cannot access "` + p + `"`:
				absent[p] = true
			}
		}
	}
	return absent
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

// lsLongLine splits an `LC_ALL=C ls -ldn` line into mode, uid, size and the
// name (plus " -> target" for a link). The date takes three
// fields in the C locale.
var lsLongLine = regexp.MustCompile(`^(\S{10})\S*\s+\d+\s+(\d+)\s+\d+\s+(\d+)\s+\S+\s+\S+\s+\S+ (.+)$`)

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
		size, err := strconv.ParseInt(m[3], 10, 64)
		if err != nil {
			continue
		}
		e := pathEntry{mode: m[1], uid: uid, size: size}
		name := m[4]
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
// directory, which was checked), but the walk continues at their target.
// lstat reports paths without following them; it is called with every
// component up to the next link or "..", so a resolution costs about one
// call per link. It returns the resolved path, and the reason it is
// untrusted (empty when it is trusted). An untrusted component does not stop
// the walk, so the resolved path is still known for reading files next to the
// binary; a component that cannot be listed does, and the resolved path is
// then empty.
func trustedResolution(p string, uid int64, lstat func([]string) lsResult) (string, string) {
	target, _, reason, _ := resolveTrusted(p, uid, lstat, false)
	return target, reason
}

// resolveTrusted is trustedResolution for a file (wantDir false) or a
// directory (wantDir true), and also returns what ls reported for the
// resolved path. missing reports that ls found a component does not exist
// while every component before it is trusted: nobody but root or uid can
// create it then. A component ls could not list is never missing.
//
// ".." is applied to the directory the walk has reached, links resolved, as
// the kernel does, not to the text of the path: in "sub/../bin" where sub is
// a link, ".." leaves the link's target.
func resolveTrusted(p string, uid int64, lstat func([]string) lsResult, wantDir bool) (target string, entry pathEntry, reason string, missing bool) {
	trusted := func(e pathEntry) bool {
		return (e.uid == 0 || e.uid == uid) && !e.writableByOthers()
	}
	if !strings.HasPrefix(p, "/") {
		return "", pathEntry{}, p + " is not absolute", false
	}

	// dir is where the walk is: every directory up to it was checked, and
	// seen holds what ls reported for them. "" until / is checked.
	dir := ""
	seen := map[string]pathEntry{}
	comps := pathComponents(p)
	hops := 0
	for {
		// list dir's components up to the next ".." in one call
		var batch []string
		var at []int // index in comps of each batch entry, -1 for /
		next := dir
		if next == "" {
			next = "/"
			batch, at = append(batch, "/"), append(at, -1)
		}
		n := 0
		for n < len(comps) && comps[n] != ".." {
			next = path.Join(next, comps[n])
			batch, at = append(batch, next), append(at, n)
			n++
		}
		restarted := false
		if len(batch) > 0 {
			res := lstat(batch)
			for i, q := range batch {
				e, ok := res.entries[q]
				if !ok {
					if reason != "" {
						return "", pathEntry{}, reason, false
					}
					if res.absent[q] {
						return "", pathEntry{}, q + " does not exist", true
					}
					return "", pathEntry{}, q + " cannot be listed", false
				}
				rest := comps[at[i]+1:]
				if e.isLink() && at[i] >= 0 {
					hops++
					if hops > maxLinkHops {
						return "", pathEntry{}, "too many symbolic links at " + q, false
					}
					// continue at the link's target, from / or from the
					// directory holding the link, both checked already
					if strings.HasPrefix(e.link, "/") {
						dir = "/"
					} else {
						dir = path.Dir(q)
					}
					comps = append(pathComponents(e.link), rest...)
					restarted = true
					break
				}
				if !trusted(e) && reason == "" {
					reason = q + " is owned by uid " + strconv.FormatInt(e.uid, 10) + " with mode " + e.mode
				}
				if len(rest) > 0 && !e.isDir() {
					return "", pathEntry{}, q + " is not a directory", false
				}
				dir, seen[q] = q, e
			}
		}
		if restarted {
			continue
		}
		comps = comps[n:]
		if len(comps) == 0 {
			break
		}
		// comps[0] is "..": dir is a checked directory, and so is its parent
		dir = path.Dir(dir)
		comps = comps[1:]
	}

	entry = seen[dir]
	if entry.isDir() != wantDir {
		if wantDir {
			return "", pathEntry{}, dir + " is not a directory", false
		}
		return "", pathEntry{}, dir + " is a directory", false
	}
	return dir, entry, reason, false
}

// pathComponents splits a path into its names, dropping empty ones and "."
// and keeping "..": "/usr//bin/./../x" gives "usr", "bin", "..", "x".
func pathComponents(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" && c != "." {
			out = append(out, c)
		}
	}
	return out
}

// execProbe is what trustedExecutable reads from the target.
type execProbe struct {
	// uid is the account commands run as.
	uid int64
	// lstat reports paths without following them (see trustedResolution).
	lstat func([]string) lsResult
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
	target, entry, reason, _ := resolveTrusted(p, x.uid, x.lstat, false)
	if reason != "" {
		return target, reason
	}
	head, err := x.head(target)
	if err != nil {
		// root reads every file, so a file root cannot read is refused. An
		// unprivileged account may be denied reading a file it may execute
		// (RHEL ships sudo as mode 4111). The file and its directories passed
		// the check above, so only root or the scan's account can replace it.
		// Its #! line goes unchecked: if it were a script, the kernel would
		// ignore a setuid bit on it and run the interpreter with the scan
		// account's privileges. Any other read error is refused.
		if x.uid != 0 && errors.Is(err, fs.ErrPermission) {
			return target, ""
		}
		return target, err.Error()
	}
	if len(head) == 0 && entry.size > 0 {
		// a read that returned nothing from a file that is not empty cannot
		// tell a script from a binary
		return target, "read nothing from " + target + ", which holds " + strconv.FormatInt(entry.size, 10) + " bytes"
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
// executable name must pass the check, then that file must. A directory or
// file is skipped as absent only when ls reported it does not exist.
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
		resolved, _, reason, missing := resolveTrusted(dir, x.uid, x.lstat, true)
		if missing {
			continue
		}
		if reason != "" {
			return "PATH entry " + dir + ": " + reason
		}
		candidate := path.Join(resolved, name)
		res := x.lstat([]string{candidate})
		e, found := res.entries[candidate]
		if !found {
			if res.absent[candidate] {
				continue
			}
			return "PATH entry " + dir + ": " + candidate + " cannot be listed"
		}
		if e.isDir() || (!e.isLink() && !e.executable()) {
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
// than -S may change it too, so both are refused. With -S, env itself splits
// the string and gives quotes, backslashes, $ and a leading # their own
// meaning; a word holding one of them is refused rather than guessed at.
func envProgram(arg string) (string, string) {
	split := false
	for _, f := range strings.Fields(arg) {
		switch {
		case f == "-S" || f == "--split-string":
			split = true
			continue
		case strings.HasPrefix(f, "-"):
			return "", "env option " + f + " is not understood"
		case strings.HasPrefix(strings.TrimLeft(f, `"'`), "PATH="):
			return "", "env changes PATH"
		case split && (strings.ContainsAny(f, `"'\$`) || strings.HasPrefix(f, "#")):
			return "", "env -S word " + f + " is not understood"
		case strings.Contains(f, "="):
			continue
		default:
			return f, ""
		}
	}
	return "", "env names no program"
}

// shellQuoteAll single-quotes each path and joins them with spaces.
func shellQuoteAll(paths []string) string {
	quoted := make([]string, len(paths))
	for i, p := range paths {
		quoted[i] = shellQuote(p)
	}
	return strings.Join(quoted, " ")
}
