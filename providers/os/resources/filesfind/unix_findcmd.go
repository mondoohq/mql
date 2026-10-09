// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package filesfind

import (
	"fmt"
	"strconv"
	"strings"
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

// FindFlavor says what the target's find supports.
type FindFlavor struct {
	// GNU is GNU findutils, which has -xtype.
	GNU bool
	// NoMaxDepth is a find without -maxdepth (AIX), which rejects the option
	// and prints nothing; the depth is then kept by pruning every path below
	// it, which POSIX find supports.
	NoMaxDepth bool
}

// BuildFilesFindCmd builds the find command of a files.find search.
func BuildFilesFindCmd(from string, xdev bool, fileType string, regex string, permission int64, search string, depth *int64, flavor FindFlavor) string {
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

	pruneLinks := !isLinkSearch && hasGNUFind
	if pruneLinks {
		call.WriteString(" \\( -xtype l -prune -o -true \\)")
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

	if pruneLinks || pruneDepth {
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
