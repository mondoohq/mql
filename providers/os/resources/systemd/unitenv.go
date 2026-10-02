// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package systemd

import (
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/afero"
)

// UnitDirs are the directories a system unit and its drop-ins are looked up in,
// in ascending order of precedence. A unit file is taken from the first of
// these that has one; drop-ins are collected from all of them.
var UnitDirs = []string{
	// /lib is a compatibility symlink to /usr/lib on a merged-usr system, so
	// both name the same file. /usr/lib is ranked above it to report the path
	// systemd itself reports rather than the alias.
	"/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/run/systemd/system",
	"/etc/systemd/system",
}

// UnitEnv is the environment a systemd service hands the process it starts,
// resolved from the unit file and its drop-ins without running systemd.
type UnitEnv struct {
	// Vars holds the resolved variables, after every override has been applied.
	Vars map[string]string
	// Sources maps a variable to the file its winning assignment came from, so
	// a reader can tell a unit's own setting from a drop-in or an env file.
	Sources map[string]string
	// FragmentPath is the unit file the settings were read from, empty when the
	// unit is not installed.
	FragmentPath string
	// DropInPaths are the drop-in files that were applied, in the order they
	// were applied.
	DropInPaths []string
	// EnvironmentFilePaths are the EnvironmentFile= targets that were read.
	// A target marked optional with "-" that does not exist is not listed.
	EnvironmentFilePaths []string
	// User is the account the service runs as, from User=. Empty when the unit
	// names none, in which case a system service runs as root.
	User string
	// ExecStart is the command line the unit starts, verbatim. Its first token
	// locates the binary without having to guess at installation paths.
	ExecStart string
}

// Files returns every file that contributed to the resolved environment.
func (e *UnitEnv) Files() []string {
	var out []string
	if e.FragmentPath != "" {
		out = append(out, e.FragmentPath)
	}
	out = append(out, e.DropInPaths...)
	return append(out, e.EnvironmentFilePaths...)
}

// ResolveUnitEnv resolves a unit's environment the way current systemd
// releases (239 and later) read it. Use ResolveUnitEnvForVersion when the
// target's systemd version is known.
func ResolveUnitEnv(afs *afero.Afero, unitName string) (*UnitEnv, bool) {
	return ResolveUnitEnvForVersion(afs, unitName, 0)
}

// ResolveUnitEnvForVersion resolves the environment of a system unit (e.g. "ollama.service")
// from the target's filesystem, following systemd's own precedence rules:
//
//   - the unit file is taken from the highest-precedence directory that has one,
//   - drop-ins are applied after it, ordered lexicographically by file name
//     across every drop-in directory (see findDropIns for which directories and
//     which copy wins when two carry the same name),
//   - an empty Environment= or EnvironmentFile= assignment resets what came before,
//   - and EnvironmentFile= targets override Environment= regardless of the order
//     the two appear in, as documented in systemd.exec(5).
//
// systemdVersion is the target's systemd version, 0 when unknown. Releases
// before 239 read only the unit's own drop-in directories; unknown is treated
// as a current release.
//
// It reports false when the unit is not installed. A unit with no environment
// settings at all resolves to an empty, non-nil map.
func ResolveUnitEnvForVersion(afs *afero.Afero, unitName string, systemdVersion int) (*UnitEnv, bool) {
	env := &UnitEnv{Vars: map[string]string{}, Sources: map[string]string{}}

	fragment, ok := findFragment(afs, unitName)
	if !ok {
		return env, false
	}
	env.FragmentPath = fragment
	env.DropInPaths = findDropIns(afs, unitName, systemdVersion)

	// Environment= assignments and the EnvironmentFile= list accumulate across
	// the fragment and every drop-in before any file is read, because a later
	// drop-in may reset either list.
	inline := map[string]string{}
	inlineSource := map[string]string{}
	var envFiles []string

	for _, p := range append([]string{fragment}, env.DropInPaths...) {
		content, err := afs.ReadFile(p)
		if err != nil {
			continue
		}
		for _, d := range parseServiceDirectives(string(content)) {
			switch d.key {
			case "User":
				env.User = unquote(d.value)
			case "ExecStart":
				// A leading "-", "@", "+", "!" or ":" is a systemd modifier on
				// how the command runs, not part of the path.
				env.ExecStart = strings.TrimLeft(unquote(d.value), "-@+!:")
			case "Environment":
				if d.value == "" {
					inline = map[string]string{}
					inlineSource = map[string]string{}
					continue
				}
				for _, assignment := range splitQuoted(d.value) {
					// The quotes wrap the whole assignment, as in
					// Environment="OLLAMA_MODELS=/var/lib/ollama", so they come
					// off before the name is split from the value. Stripping
					// them afterwards instead leaves the quote on the name and
					// the variable is never found under the name it was given.
					k, v, found := strings.Cut(unquote(assignment), "=")
					if !found || k == "" {
						continue
					}
					inline[k] = v
					inlineSource[k] = p
				}
			case "EnvironmentFile":
				if d.value == "" {
					envFiles = nil
					continue
				}
				envFiles = append(envFiles, d.value)
			}
		}
	}

	for k, v := range inline {
		env.Vars[k] = v
		env.Sources[k] = inlineSource[k]
	}

	for _, spec := range envFiles {
		// A "-" prefix marks the file optional. Either way an unreadable file
		// contributes nothing: without it systemd refuses to start the service,
		// so guessing at what it held would invent an environment that never ran.
		pattern := unquote(strings.TrimPrefix(spec, "-"))
		if pattern == "" {
			continue
		}
		for _, p := range expandEnvFilePattern(afs, pattern) {
			content, err := afs.ReadFile(p)
			if err != nil {
				continue
			}
			env.EnvironmentFilePaths = append(env.EnvironmentFilePaths, p)
			for k, v := range ParseEnvFile(string(content)) {
				env.Vars[k] = v
				env.Sources[k] = p
			}
		}
	}

	return env, true
}

// findFragment returns the unit file from the highest-precedence directory that
// has one. /lib is usually a symlink to /usr/lib, so the same file can appear
// twice; the first hit wins and the duplicate is never read.
func findFragment(afs *afero.Afero, unitName string) (string, bool) {
	for i := len(UnitDirs) - 1; i >= 0; i-- {
		p := path.Join(UnitDirs[i], unitName)
		if ok, err := afs.Exists(p); err == nil && ok {
			return p, true
		}
	}
	return "", false
}

// typeAndPrefixDropInsSince is the first systemd release that reads type-level
// (service.d) and dash-prefix (foo-.service.d) drop-in directories. Verified
// against systemd 219 (RHEL 7) and 232 (Debian 9), which ignore them, and 239
// (RHEL 8), which reads them.
const typeAndPrefixDropInsSince = 239

// ReadsTypeAndPrefixDropIns reports whether a systemd release applies
// type-level and dash-prefix drop-in directories. An unknown version (0) is
// treated as a current release.
func ReadsTypeAndPrefixDropIns(systemdVersion int) bool {
	return systemdVersion == 0 || systemdVersion >= typeAndPrefixDropInsSince
}

// findDropIns collects the *.conf drop-ins systemd applies to a unit, as
// systemd.unit(5) describes and `systemctl show -p DropInPaths` reports them.
//
// The directories searched are, in descending precedence:
//
//  1. for each unit directory (/etc, /run, /usr/lib, /lib): the unit's own
//     <unit>.d, then each dash-truncated prefix from longest to shortest
//     (foo-bar-.service.d, foo-.service.d);
//  2. for each unit directory in the same order: the type-level directory
//     (service.d for a service).
//
// Files are applied in lexicographic order of their base name regardless of
// which directory they live in; when several directories carry the same name,
// the copy from the highest-precedence directory is the one applied. Before
// systemd 239 only the unit's own directories exist.
func findDropIns(afs *afero.Afero, unitName string, systemdVersion int) []string {
	modern := ReadsTypeAndPrefixDropIns(systemdVersion)

	names := []string{unitName}
	if modern {
		names = append(names, unitNamePrefixes(unitName)...)
	}

	var dirs []string
	for i := len(UnitDirs) - 1; i >= 0; i-- {
		for _, n := range names {
			dirs = append(dirs, path.Join(UnitDirs[i], n+".d"))
		}
	}
	if modern {
		if dot := strings.LastIndex(unitName, "."); dot >= 0 && dot < len(unitName)-1 {
			typeDir := unitName[dot+1:] + ".d"
			for i := len(UnitDirs) - 1; i >= 0; i-- {
				dirs = append(dirs, path.Join(UnitDirs[i], typeDir))
			}
		}
	}

	byName := map[string]string{}
	for _, d := range dirs {
		entries, err := afs.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			// dirs is in descending precedence, so the first copy of a name
			// is the one systemd applies.
			if _, taken := byName[e.Name()]; taken {
				continue
			}
			byName[e.Name()] = path.Join(d, e.Name())
		}
	}
	if len(byName) == 0 {
		return nil
	}

	fileNames := make([]string, 0, len(byName))
	for n := range byName {
		fileNames = append(fileNames, n)
	}
	sort.Strings(fileNames)

	out := make([]string, 0, len(fileNames))
	for _, n := range fileNames {
		out = append(out, byName[n])
	}
	return out
}

// unitNamePrefixes returns the dash-truncated prefix names of a unit, longest
// first: foo-bar-baz.service yields foo-bar-.service and foo-.service. A
// trailing dash before the type suffix is skipped, since foo-.service is not
// its own prefix.
func unitNamePrefixes(unitName string) []string {
	dot := strings.LastIndex(unitName, ".")
	if dot <= 0 {
		return nil
	}
	stem, suffix := unitName[:dot], unitName[dot:]
	stem = strings.TrimSuffix(stem, "-")

	var out []string
	for {
		dash := strings.LastIndex(stem, "-")
		if dash < 0 {
			return out
		}
		stem = stem[:dash]
		out = append(out, stem+"-"+suffix)
	}
}

// ParseSystemctlVersion reads the release number from the first line of
// `systemctl --version` ("systemd 257 (257-9.el10_0.2)"). It returns 0 when the
// output carries none.
func ParseSystemctlVersion(out string) int {
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "systemd" {
		return 0
	}
	v, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return v
}

// expandEnvFilePattern resolves an EnvironmentFile= target, which systemd allows
// to be a wildcard expression. A pattern that matches nothing yields nothing.
func expandEnvFilePattern(afs *afero.Afero, pattern string) []string {
	if !strings.ContainsAny(pattern, "*?[") {
		return []string{pattern}
	}
	matches, err := afero.Glob(afs.Fs, pattern)
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	return matches
}

type serviceDirective struct {
	key   string
	value string
}

// parseServiceDirectives returns the Environment=, EnvironmentFile=, User= and
// ExecStart= settings of a unit's [Service] section, in the order they appear. Continuation lines
// ending in a backslash are joined first, as systemd joins them.
func parseServiceDirectives(content string) []serviceDirective {
	var out []serviceDirective
	inService := false

	for _, line := range joinContinuations(content) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inService = strings.EqualFold(trimmed, "[Service]")
			continue
		}
		if !inService {
			continue
		}
		key, value, found := strings.Cut(trimmed, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key != "Environment" && key != "EnvironmentFile" && key != "User" && key != "ExecStart" {
			continue
		}
		out = append(out, serviceDirective{key: key, value: strings.TrimSpace(value)})
	}
	return out
}

// joinContinuations merges lines that systemd would treat as one, i.e. a line
// whose last character is a backslash continues into the next.
func joinContinuations(content string) []string {
	raw := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	var out []string
	var buf strings.Builder
	continuing := false

	for _, line := range raw {
		trimmedRight := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmedRight, "\\") {
			buf.WriteString(strings.TrimSuffix(trimmedRight, "\\"))
			buf.WriteString(" ")
			continuing = true
			continue
		}
		if continuing {
			buf.WriteString(trimmedRight)
			out = append(out, buf.String())
			buf.Reset()
			continuing = false
			continue
		}
		out = append(out, line)
	}
	if continuing {
		out = append(out, buf.String())
	}
	return out
}

// ParseEnvFile reads a systemd EnvironmentFile: newline-separated assignments,
// with empty lines, lines without "=", and lines starting with "#" or ";"
// ignored. Values may be quoted; surrounding quotes are stripped.
func ParseEnvFile(content string) map[string]string {
	out := map[string]string{}
	for _, line := range joinContinuations(content) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		key, value, found := strings.Cut(trimmed, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out[key] = unquote(strings.TrimSpace(value))
	}
	return out
}

// splitQuoted splits a space-separated list of assignments, keeping a quoted
// value together: `A=1 B="two words"` yields `A=1` and `B="two words"`.
func splitQuoted(s string) []string {
	var out []string
	var buf strings.Builder
	var quote rune

	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
			buf.WriteRune(r)
		case r == '"' || r == '\'':
			quote = r
			buf.WriteRune(r)
		case r == ' ' || r == '\t':
			if buf.Len() > 0 {
				out = append(out, buf.String())
				buf.Reset()
			}
		default:
			buf.WriteRune(r)
		}
	}
	if buf.Len() > 0 {
		out = append(out, buf.String())
	}
	return out
}

// unquote strips one layer of matching surrounding quotes.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return s
	}
	if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}
