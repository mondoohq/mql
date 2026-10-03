// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"path"
	"regexp"
	"strconv"
	"strings"

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
// belongs to the user who installed it.
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
		return parseLsLong(readCommandOutput(cmd.Stdout))
	}
	target, err := trustedResolution(p, uid, lstat)
	if err != "" {
		log.Debug().Str("path", p).Str("reason", err).
			Msg("mql[packages]> not executing a binary another account can replace")
		return target, false
	}
	return target, true
}

// commandUID returns the uid that commands run as on the target: root for a
// root or sudo scan.
func commandUID(conn shared.Connection) (int64, bool) {
	cmd, err := conn.RunCommand("id -u")
	if err != nil || cmd.ExitStatus != 0 {
		return 0, false
	}
	uid, err := strconv.ParseInt(strings.TrimSpace(readCommandOutput(cmd.Stdout)), 10, 64)
	if err != nil {
		return 0, false
	}
	return uid, true
}

// pathEntry is what `ls -ldn` reports for one path, without following it.
type pathEntry struct {
	mode string // the 10-character mode, e.g. "drwxr-xr-x"
	uid  int64
	link string // the link's target, for a symbolic link
}

func (e pathEntry) isLink() bool { return strings.HasPrefix(e.mode, "l") }
func (e pathEntry) isDir() bool  { return strings.HasPrefix(e.mode, "d") }

// writableByOthers reports whether group or others may write to the entry.
func (e pathEntry) writableByOthers() bool {
	return len(e.mode) >= 10 && (e.mode[5] == 'w' || e.mode[8] == 'w')
}

// lsLongLine splits an `LC_ALL=C ls -ldn` line into mode, uid and the name
// (plus " -> target" for a link). The date takes three fields in the C locale.
var lsLongLine = regexp.MustCompile(`^(\S{10})\S*\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\S+\s+\S+\s+\S+ (.+)$`)

// parseLsLong reads `LC_ALL=C ls -ldn` output, keyed by path as it was passed.
func parseLsLong(out string) map[string]pathEntry {
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
			n, target, found := strings.Cut(name, " -> ")
			if !found {
				continue
			}
			name, e.link = n, target
		}
		entries[name] = e
	}
	return entries
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
	trusted := func(e pathEntry) bool {
		return (e.uid == 0 || e.uid == uid) && !e.writableByOthers()
	}

	reason := ""
	hops := 0
	cur := path.Clean(p)
	for {
		prefixes := pathPrefixes(cur)
		entries := lstat(prefixes)
		restarted := false
		for i, prefix := range prefixes {
			e, ok := entries[prefix]
			if !ok {
				return "", prefix + " cannot be read"
			}
			if e.isLink() {
				hops++
				if hops > maxLinkHops {
					return "", "too many symbolic links at " + prefix
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
				return "", prefix + " is not a directory"
			}
			if last && e.isDir() {
				return "", prefix + " is a directory"
			}
		}
		if !restarted {
			return cur, reason
		}
	}
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
