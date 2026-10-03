// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package systemd

import (
	"path"
	"regexp"
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
// releases read it, with every drop-in directory. Use ResolveUnitEnvWithDirs
// when the target's systemd release is known, or ResolveUnitEnvWithDropIns when
// systemd itself reported the drop-ins.
func ResolveUnitEnv(afs *afero.Afero, unitName string) (*UnitEnv, bool) {
	return ResolveUnitEnvWithDirs(afs, unitName, AllDropInDirs)
}

// ResolveUnitEnvWithDirs resolves a unit's environment from the drop-in
// directories dirs selects (see findDropIns).
func ResolveUnitEnvWithDirs(afs *afero.Afero, unitName string, dirs DropInDirs) (*UnitEnv, bool) {
	return resolveUnitEnv(afs, unitName, func() []string { return findDropIns(afs, unitName, dirs) })
}

// ResolveUnitEnvWithDropIns resolves a unit's environment from the drop-ins
// systemd reported for it (`systemctl show -p DropInPaths`), in the order given.
func ResolveUnitEnvWithDropIns(afs *afero.Afero, unitName string, dropIns []string) (*UnitEnv, bool) {
	return resolveUnitEnv(afs, unitName, func() []string { return dropIns })
}

// resolveUnitEnv resolves the environment of a system unit (e.g. "ollama.service")
// from the target's filesystem, following systemd's own precedence rules:
//
//   - the unit file is taken from the highest-precedence directory that has one,
//   - drop-ins (from dropIns, in order) are applied after it,
//   - an empty Environment= or EnvironmentFile= assignment resets what came before,
//   - and EnvironmentFile= targets override Environment= regardless of the order
//     the two appear in, as documented in systemd.exec(5).
//
// It reports false when the unit is not installed. A unit with no environment
// settings at all resolves to an empty, non-nil map.
func resolveUnitEnv(afs *afero.Afero, unitName string, dropIns func() []string) (*UnitEnv, bool) {
	env := &UnitEnv{Vars: map[string]string{}, Sources: map[string]string{}}

	fragment, ok := findFragment(afs, unitName)
	if !ok {
		return env, false
	}
	env.FragmentPath = fragment
	env.DropInPaths = dropIns()

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

// DropInDirs selects which drop-in directories systemd reads for a unit
// besides the unit's own <unit>.d.
type DropInDirs struct {
	// Prefix covers the dash-truncated prefix directories (foo-.service.d for
	// foo-bar.service), read since systemd 239.
	Prefix bool
	// TypeLevel covers the unit type's directory (service.d for every service),
	// read since systemd 244.
	TypeLevel bool
}

// AllDropInDirs is how current systemd releases read drop-ins.
var AllDropInDirs = DropInDirs{Prefix: true, TypeLevel: true}

const (
	// prefixDropInsSince: systemd 232 (Debian 9) ignores foo-.service.d,
	// 241 (Debian 10) reads it.
	prefixDropInsSince = 239
	// typeLevelDropInsSince: systemd NEWS lists <type>.d/ drop-ins under
	// "CHANGES WITH 244". 241 (Debian 10) ignores service.d, 245 (Ubuntu
	// 20.04) reads it.
	typeLevelDropInsSince = 244
)

// DropInDirsForVersion returns the drop-in directories a systemd release
// reads. An unknown version (0) reads like a current release.
//
// typeLevelBackport marks a distribution that backported type-level drop-ins
// to an older release: RHEL 8 and its rebuilds ship systemd 239 with
// service.d support.
func DropInDirsForVersion(systemdVersion int, typeLevelBackport bool) DropInDirs {
	if systemdVersion == 0 {
		return AllDropInDirs
	}
	return DropInDirs{
		Prefix:    systemdVersion >= prefixDropInsSince,
		TypeLevel: systemdVersion >= typeLevelDropInsSince || (typeLevelBackport && systemdVersion >= prefixDropInsSince),
	}
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
// the copy from the highest-precedence directory is the one applied. dirs
// leaves out the prefix or type-level directories for releases that ignore
// them.
func findDropIns(afs *afero.Afero, unitName string, dirs DropInDirs) []string {
	names := []string{unitName}
	if dirs.Prefix {
		names = append(names, unitNamePrefixes(unitName)...)
	}

	var searched []string
	for i := len(UnitDirs) - 1; i >= 0; i-- {
		for _, n := range names {
			searched = append(searched, path.Join(UnitDirs[i], n+".d"))
		}
	}
	if dirs.TypeLevel {
		if dot := strings.LastIndex(unitName, "."); dot >= 0 && dot < len(unitName)-1 {
			typeDir := unitName[dot+1:] + ".d"
			for i := len(UnitDirs) - 1; i >= 0; i-- {
				searched = append(searched, path.Join(UnitDirs[i], typeDir))
			}
		}
	}

	byName := map[string]string{}
	for _, d := range searched {
		entries, err := afs.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			// searched is in descending precedence, so the first copy of a name
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

// ParseDropInPaths reads the output of
// `systemctl show <unit> -p LoadState -p DropInPaths`. It reports false unless
// systemd loaded the unit, since only then is the list the one systemd applies.
// systemd prints the properties in its own order, one KEY=value per line, and
// the paths space-separated.
func ParseDropInPaths(out string) ([]string, bool) {
	var loaded, seen bool
	var paths []string
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "LoadState":
			loaded = v == "loaded"
		case "DropInPaths":
			seen = true
			paths = strings.Fields(v)
		}
	}
	if !loaded || !seen {
		return nil, false
	}
	return paths, true
}

// sharedLibraryGlobs locate systemd's private shared library, whose file name
// carries the release (libsystemd-shared-241.so on Debian 10). Debian puts it
// in /lib/systemd before the /usr merge and under the multiarch directory from
// Debian 12 on. SUSE puts it in /usr/lib64/systemd, on SLES with the full
// package version (libsystemd-shared-254.27-150600.4.71.2.so).
var sharedLibraryGlobs = []string{
	"/usr/lib/systemd/libsystemd-shared-*.so",
	"/lib/systemd/libsystemd-shared-*.so",
	"/usr/lib64/systemd/libsystemd-shared-*.so",
	"/usr/lib/*-linux-gnu*/systemd/libsystemd-shared-*.so",
}

// managerBinaries are where the systemd manager binary sits, before and after
// the /usr merge.
var managerBinaries = []string{
	"/usr/lib/systemd/systemd",
	"/lib/systemd/systemd",
}

// managerVersionLine matches the log line the manager prints at start-up,
// compiled into its binary as "systemd 219 running in %ssystem mode".
var managerVersionLine = regexp.MustCompile(`systemd (\d{2,3}) running in `)

// preSharedLibraryVersion stands in for a release that predates
// libsystemd-shared when the binary does not say which one it is.
const preSharedLibraryVersion = 230

// maxManagerBinarySize bounds how much of a manager binary is read for its
// release. systemd 219's is 1.6 MB.
const maxManagerBinarySize = 16 << 20

// InstalledVersion reads the systemd release installed on a filesystem without
// running anything, from the name of libsystemd-shared, which systemd ships
// since 231. A filesystem with a manager binary but no libsystemd-shared runs
// an older release (systemd 219 on RHEL 7), read from the binary, or 230 when
// the binary does not say. It returns 0 when there is no systemd.
func InstalledVersion(afs *afero.Afero) int {
	if v := sharedLibraryVersion(afs); v != 0 {
		return v
	}
	for _, p := range managerBinaries {
		fi, err := afs.Stat(p)
		if err != nil || fi.IsDir() {
			continue
		}
		if fi.Size() <= maxManagerBinarySize {
			if data, err := afs.ReadFile(p); err == nil {
				if m := managerVersionLine.FindSubmatch(data); m != nil {
					if v, err := strconv.Atoi(string(m[1])); err == nil && v < 231 {
						return v
					}
				}
			}
		}
		return preSharedLibraryVersion
	}
	return 0
}

// sharedLibraryVersion reads the release from the name of libsystemd-shared,
// 0 when there is none.
func sharedLibraryVersion(afs *afero.Afero) int {
	best := 0
	for _, g := range sharedLibraryGlobs {
		matches, err := afero.Glob(afs.Fs, g)
		if err != nil {
			continue
		}
		for _, m := range matches {
			name := strings.TrimPrefix(path.Base(m), "libsystemd-shared-")
			end := 0
			for end < len(name) && name[end] >= '0' && name[end] <= '9' {
				end++
			}
			if v, err := strconv.Atoi(name[:end]); err == nil && v > best {
				best = v
			}
		}
	}
	return best
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
