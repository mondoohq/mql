// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package nfs

import (
	"io"
	"slices"
	"strings"
)

// parseBSDExports parses /etc/exports in the syntax used by the
// FreeBSD and macOS NFS servers. A line is
//
//	path1 [path2 ...] [-flag ...] [host ...]
//
// where paths come first (each starts with `/`), flags start with
// `-` and may take a value via `=` (FreeBSD) or as a separate token
// (macOS, e.g. `-network 192.168.1.0`), and any remaining tokens are
// hosts. The same set of flags and hosts applies to each path; one
// [ExportEntry] is emitted per (path, host) pair, with `*` substituted
// when no hosts are listed. Lines beginning with `V4:` declare the
// NFSv4 root and are skipped.
func parseBSDExports(r io.Reader) ([]ExportEntry, error) {
	var entries []ExportEntry
	err := scanExportLines(r, func(line string) error {
		if strings.HasPrefix(line, "V4:") {
			return nil
		}
		paths, options, hosts := splitBSDLine(line)
		if len(paths) == 0 {
			return nil
		}
		if len(hosts) == 0 {
			hosts = []string{"*"}
		}
		ro := bsdReadOnly(options)
		nrs := bsdNoRootSquash(options)
		for _, p := range paths {
			for _, h := range hosts {
				entries = append(entries, ExportEntry{
					Path:         p,
					Client:       h,
					Options:      options,
					ReadOnly:     ro,
					NoRootSquash: nrs,
				})
			}
		}
		return nil
	})
	return entries, err
}

// bsdValueFlags lists flag names that consume a following token as
// their value when the flag is given without an `=`. The set comes
// from the FreeBSD and macOS exports(5) man pages.
var bsdValueFlags = map[string]bool{
	"-network": true,
	"-mask":    true,
	"-index":   true,
	"-sec":     true,
}

// splitBSDLine classifies a tokenized export line into paths, flags
// (with their values), and host entries. Path tokens (starting with
// `/`) may only appear before any flag or host. Flag tokens (starting
// with `-`) accumulate values either via `=` or by consuming the next
// token when the flag name is listed in [bsdValueFlags].
func splitBSDLine(line string) (paths, options, hosts []string) {
	tokens := strings.Fields(line)
	pathPhase := true
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		switch {
		case pathPhase && strings.HasPrefix(tok, "/"):
			paths = append(paths, tok)
		case strings.HasPrefix(tok, "-"):
			pathPhase = false
			name, value, hasValue := cutOnce(tok, "=")
			if hasValue {
				options = append(options, name+"="+value)
				continue
			}
			if bsdValueFlags[tok] && i+1 < len(tokens) {
				i++
				options = append(options, tok+"="+tokens[i])
				continue
			}
			options = append(options, tok)
		default:
			pathPhase = false
			hosts = append(hosts, tok)
		}
	}
	return paths, options, hosts
}

func bsdReadOnly(options []string) bool {
	return slices.Contains(options, "-ro")
}

func bsdNoRootSquash(options []string) bool {
	for _, o := range options {
		v, ok := strings.CutPrefix(o, "-maproot=")
		if !ok {
			continue
		}
		// -maproot=root, -maproot=0, -maproot=0:0, -maproot=0:wheel
		if v == "root" || v == "0" {
			return true
		}
		if id, _, ok := cutOnce(v, ":"); ok && (id == "0" || id == "root") {
			return true
		}
	}
	return false
}

// cutOnce is strings.Cut with explicit naming for readability.
func cutOnce(s, sep string) (before, after string, found bool) {
	return strings.Cut(s, sep)
}
