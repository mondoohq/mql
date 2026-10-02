// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package filesfind

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/mount"
)

var findTypes = map[string]string{
	"file":      "f",
	"directory": "d",
	"character": "c",
	"block":     "b",
	"socket":    "s",
	"link":      "l",
}

func Octal2string(o int64) string {
	return fmt.Sprintf("%o", o)
}

// shellSingleQuote wraps s in single quotes so the shell passes it to the
// command verbatim, with no glob, variable, or command-substitution expansion.
// Any single quote in s is escaped by closing, inserting an escaped quote, then reopening.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// globEscape escapes the characters find's -path treats as a pattern, so
// the start path matches only itself.
func globEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '*', '?', '[':
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// FindFlavor says what the target's find supports.
type FindFlavor struct {
	// GNU is GNU findutils, which has -xtype.
	GNU bool
	// NoMaxDepth is a find without -maxdepth (AIX, Solaris), which rejects the option
	// and prints nothing; the depth is then kept by pruning every path below
	// it, which POSIX find supports.
	NoMaxDepth bool
}

// BuildFilesFindCmd builds the find command of a files.find search.
func BuildFilesFindCmd(from string, xdev bool, fileType string, regex string, permission int64, search string, depth *int64, flavor FindFlavor) string {
	return buildFindCmd(from, xdev, nil, fileType, regex, permission, search, depth, flavor)
}

// BuildFilesFindCmdPruningMounts builds the command for a search that stays on
// the filesystem holding from without -xdev: find does not descend into the
// given mount points, which MountPrunes returns, and enters every other
// directory, including a Btrfs subvolume that is not mounted. A mount point
// itself is still tested, as -xdev tests it.
func BuildFilesFindCmdPruningMounts(from string, mounts []string, fileType string, regex string, permission int64, search string, depth *int64, flavor FindFlavor) string {
	return buildFindCmd(path.Clean(from), true, mounts, fileType, regex, permission, search, depth, flavor)
}

func buildFindCmd(from string, xdev bool, pruneMounts []string, fileType string, regex string, permission int64, search string, depth *int64, flavor FindFlavor) string {
	hasGNUFind, noMaxDepth := flavor.GNU, flavor.NoMaxDepth
	var call strings.Builder

	isLinkSearch := false
	if fileType != "" {
		if t, ok := findTypes[fileType]; ok && t == "l" {
			isLinkSearch = true
		}
	}

	// Symlinks are matched by their target, like the native walk in fsutil and
	// like `find -L`: a symlink to a regular file is a "file", and -type and
	// -perm test the target, not the link (a symlink's own mode is always
	// 0777). authselect's /etc/pam.d/system-auth is such a symlink; without -L,
	// pam.conf never parsed it (mql#8467).
	//
	// Plain -L also walks into every symlinked directory, which is slow on
	// hosts with many symlinks and can hang on a stale mount. Under -L,
	// `-xtype l` is still true for a symlink, so GNU find prunes on it: the
	// tests see the target, but the walk never descends through a link.
	// -prune suppresses the implicit -print, so the command ends with one.
	// The start path is exempt from the prune: on a usr-merged host /bin,
	// /sbin and /lib are themselves symlinks, and pruning them found nothing.
	//
	// Link searches: GNU find uses -L -xtype l, which follows all symlinks and
	// finds them. BSD and BusyBox find have no -xtype. They fall back to -H
	// -type l for link searches, which follows only the start path but still
	// detects symlinks, and to plain -L for everything else.
	if isLinkSearch && !hasGNUFind {
		call.WriteString("find -H ")
	} else {
		call.WriteString("find -L ")
	}
	call.WriteString(strconv.Quote(from))

	if !xdev {
		call.WriteString(" -xdev")
	}

	if len(pruneMounts) > 0 {
		call.WriteString(" \\( -type d \\(")
		for i, m := range pruneMounts {
			if i > 0 {
				call.WriteString(" -o")
			}
			call.WriteString(" -path ")
			call.WriteString(shellSingleQuote(globEscape(m)))
		}
		call.WriteString(" \\) -prune -o -true \\)")
	}

	pruneLinks := !isLinkSearch && hasGNUFind
	if pruneLinks {
		call.WriteString(" \\( -path ")
		call.WriteString(shellSingleQuote(globEscape(from)))
		call.WriteString(" -o -xtype l -prune -o -true \\)")
	}

	// -prune suppresses find's implicit -print, so the command ends with one.
	pruneDepth := depth != nil && noMaxDepth
	if pruneDepth {
		call.WriteString(" -path ")
		call.WriteString(shellSingleQuote(depthPrunePattern(from, *depth)))
		call.WriteString(" -prune -o")
	}

	if fileType != "" {
		t, ok := findTypes[fileType]
		if ok {
			if t == "l" && hasGNUFind {
				call.WriteString(" -xtype " + t)
			} else {
				call.WriteString(" -type " + t)
			}
		}
	}

	if regex != "" {
		call.WriteString(" -regex ")
		call.WriteString(shellSingleQuote(regex))
	}

	if permission != 0o777 {
		call.WriteString(" -perm -")
		call.WriteString(Octal2string(permission))
	}

	if search != "" {
		call.WriteString(" -name ")
		// Single-quote the pattern so the shell passes it to find verbatim,
		// with no glob, variable, or command-substitution expansion.
		call.WriteString(shellSingleQuote(search))
	}

	if depth != nil && !noMaxDepth {
		call.WriteString(" -maxdepth ")
		// -maxdepth takes a decimal level count, not an octal value.
		call.WriteString(strconv.FormatInt(*depth, 10))
	}

	if pruneLinks || pruneDepth || len(pruneMounts) > 0 {
		// -prune suppresses find's implicit -print.
		call.WriteString(" -print")
	}
	return call.String()
}

// depthPrunePattern returns the -path pattern of the paths more than depth
// levels below from: from/?*/?* for depth 1. Glob characters in from are
// escaped, so they match themselves.
func depthPrunePattern(from string, depth int64) string {
	base := strings.TrimRight(from, "/")
	var escaped strings.Builder
	for _, r := range base {
		if strings.ContainsRune(`*?[]\`, r) {
			escaped.WriteRune('\\')
		}
		escaped.WriteRune(r)
	}
	if depth < 0 {
		depth = 0
	}
	// ?* rather than *: a component is never empty, and /* would match the
	// root itself
	return escaped.String() + strings.Repeat("/?*", int(depth)+1)
}

// globEscape escapes the characters find's -path treats as a pattern, so a
// mount point is matched literally.
func globEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '*', '?', '[', ']', '\\':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Filesystems whose subvolumes each carry a device number of their own,
// whether or not they are mounted. find's -xdev compares device numbers, so on
// these it skips a subvolume nested in the directory tree as if it were another
// mounted filesystem: snapper's .snapshots, the subvolumes podman, docker and
// systemd-nspawn create under /var/lib, or any `btrfs subvolume create`.
var subvolumeFsTypes = map[string]bool{
	"btrfs":    true,
	"bcachefs": true,
}

// MountPrunes decides how a search from `from` stays on the filesystem that
// holds it. On a filesystem with subvolumes it returns the mount points below
// from, outermost first, and true: the search must prune those rather than use
// -xdev. Otherwise, and when from is not an absolute path or no mount holds
// it, it returns false and -xdev is right.
func MountPrunes(from string, mounts []mount.MountPoint) ([]string, bool) {
	if !path.IsAbs(from) {
		return nil, false
	}
	from = path.Clean(from)

	// The mount holding from is the one with the longest mount point that is
	// from or one of its parents. Of several mounts on one path the last is
	// the one visible.
	holder := -1
	for i, m := range mounts {
		mp := m.MountPoint
		if mp != from && mp != "/" && !strings.HasPrefix(from, mp+"/") {
			continue
		}
		if holder < 0 || len(mp) >= len(mounts[holder].MountPoint) {
			holder = i
		}
	}
	if holder < 0 || !subvolumeFsTypes[mounts[holder].FSType] {
		return nil, false
	}

	prefix := from + "/"
	if from == "/" {
		prefix = "/"
	}
	below := []string{}
	for _, m := range mounts {
		if m.MountPoint != from && strings.HasPrefix(m.MountPoint, prefix) {
			below = append(below, m.MountPoint)
		}
	}
	sort.Strings(below)

	// A mount below one that is already pruned is never reached.
	prunes := []string{}
	for _, mp := range below {
		if !underAny(mp, prunes) {
			prunes = append(prunes, mp)
		}
	}
	return prunes, true
}

func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}
