// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sudoers

import (
	"path"
	"strings"
)

// ResolveIncludePath turns the argument of an @include/@includedir (or
// #include/#includedir) directive into the path sudo opens.
//
// sudo (1.9.1+) resolves a path that does not start with '/' against the
// directory of the file holding the directive, not against its working
// directory, and expands %h to the short host name (the host name up to the
// first dot). The argument may be double-quoted, or escape spaces with a
// backslash. shortHost is called only when the path contains %h; when it
// returns "", %h is left as written.
func ResolveIncludePath(includingFile string, arg string, shortHost func() string) string {
	p := unquoteIncludeArg(strings.TrimSpace(arg))

	if strings.Contains(p, "%h") && shortHost != nil {
		if host := ShortHostname(shortHost()); host != "" {
			p = strings.ReplaceAll(p, "%h", host)
		}
	}

	if !strings.HasPrefix(p, "/") && includingFile != "" {
		p = path.Join(path.Dir(includingFile), p)
	}
	return path.Clean(p)
}

// ShortHostname returns the host name up to its first dot, the form sudo
// substitutes for %h.
func ShortHostname(host string) string {
	host = strings.TrimSpace(host)
	if i := strings.IndexByte(host, '.'); i >= 0 {
		return host[:i]
	}
	return host
}

// unquoteIncludeArg strips the double quotes sudo allows around an include
// path and resolves backslash escapes (`\"`, `\\`, `\ `).
func unquoteIncludeArg(arg string) string {
	if len(arg) >= 2 && arg[0] == '"' && arg[len(arg)-1] == '"' {
		arg = arg[1 : len(arg)-1]
	}
	if !strings.Contains(arg, `\`) {
		return arg
	}
	var b strings.Builder
	for i := 0; i < len(arg); i++ {
		if arg[i] == '\\' && i+1 < len(arg) {
			i++
		}
		b.WriteByte(arg[i])
	}
	return b.String()
}

// IsIncludedirEntry reports whether sudo reads filePath (named basename)
// when it processes `@includedir dir`. sudo reads only the regular files
// directly inside dir, never files in subdirectories, and skips any name that
// ends in '~' or contains a '.', which keeps editor backups and package
// manager leftovers (.rpmnew, .dpkg-old) out of the policy.
func IsIncludedirEntry(dir string, filePath string, basename string) bool {
	if path.Clean(path.Dir(filePath)) != path.Clean(dir) {
		return false
	}
	if basename == "" || strings.HasSuffix(basename, "~") || strings.Contains(basename, ".") {
		return false
	}
	return true
}
