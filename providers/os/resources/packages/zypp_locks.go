// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"errors"
	iofs "io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/afero"
)

// libzypp reads its configuration UAPI style: /etc/zypp/zypp.conf replaces the
// vendor /usr/etc/zypp/zypp.conf, and the drop-ins of both conf.d directories
// are read after it in file name order, a drop-in in /etc replacing the one of
// the same name in /usr/etc. Later settings win. See zypp.conf(5).
const (
	zyppConfPath       = "/etc/zypp/zypp.conf"
	zyppVendorConfPath = "/usr/etc/zypp/zypp.conf"
	zyppDefaultConfDir = "/etc/zypp"
)

var zyppConfDropinDirs = []string{"/usr/etc/zypp/zypp.conf.d", "/etc/zypp/zypp.conf.d"}

// zyppLockConfig is what zypp.conf says about the lock store.
type zyppLockConfig struct {
	// path is the store, locksfile.path ({configdir}/locks).
	path string
	// apply is false when locksfile.apply turns the store off: zypper then
	// ignores every lock in it.
	apply bool
}

// readZyppLockConfig reads where zypper keeps its locks and whether it applies
// them. The ZYPP_CONF environment variable is not read: it overrides the
// configuration for the one process that sets it, so it says nothing about
// how the host's zypper behaves.
func readZyppLockConfig(fs afero.Fs) (zyppLockConfig, error) {
	var files [][]byte

	base, err := readLockStore(fs, zyppConfPath)
	if err != nil {
		return zyppLockConfig{}, err
	}
	if base == nil {
		if base, err = readLockStore(fs, zyppVendorConfPath); err != nil {
			return zyppLockConfig{}, err
		}
	}
	if base != nil {
		files = append(files, base)
	}

	dropins := map[string]string{}
	for _, dir := range zyppConfDropinDirs {
		entries, err := afero.ReadDir(fs, dir)
		if err != nil {
			if errors.Is(err, iofs.ErrNotExist) {
				continue
			}
			return zyppLockConfig{}, err
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				dropins[e.Name()] = path.Join(dir, e.Name())
			}
		}
	}
	names := make([]string, 0, len(dropins))
	for name := range dropins {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw, err := readLockStore(fs, dropins[name])
		if err != nil {
			return zyppLockConfig{}, err
		}
		if raw != nil {
			files = append(files, raw)
		}
	}

	return parseZyppLockConfig(files...), nil
}

// parseZyppLockConfig reads the [main] keys that decide which locks zypper
// applies, from each file in turn.
func parseZyppLockConfig(files ...[]byte) zyppLockConfig {
	configDir := zyppDefaultConfDir
	locksPath := ""
	apply := true
	for _, raw := range files {
		inMain := false
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' {
				continue
			}
			if line[0] == '[' {
				inMain = strings.TrimSpace(strings.Trim(line, "[]")) == "main"
				continue
			}
			if !inMain {
				continue
			}
			key, value, found := strings.Cut(line, "=")
			if !found {
				continue
			}
			value = strings.TrimSpace(value)
			switch strings.TrimSpace(key) {
			case "configdir":
				if value != "" {
					configDir = value
				}
			case "locksfile.path":
				locksPath = value
			case "locksfile.apply":
				switch strings.ToLower(value) {
				case "1", "yes", "on", "true":
					apply = true
				case "0", "no", "off", "false":
					apply = false
				}
			}
		}
	}
	if locksPath == "" {
		locksPath = path.Join(configDir, "locks")
	}
	return zyppLockConfig{path: locksPath, apply: apply}
}

// readZypperLocks returns the locks zypper applies. A missing store means
// nothing is locked. A store or configuration that exists but cannot be read
// is an error: nothing is known about the locks it holds.
func readZypperLocks(fs afero.Fs) (zypperLocks, error) {
	conf, err := readZyppLockConfig(fs)
	if err != nil {
		return nil, err
	}
	if !conf.apply {
		return nil, nil
	}
	raw, err := readLockStore(fs, conf.path)
	if err != nil {
		return nil, err
	}
	return parseZypperLocks(string(raw)), nil
}

// zypperLock is one paragraph of the store, a libzypp query:
//
//	type: package
//	version: < 1.0
//	match_type: glob
//	case_sensitive: on
//	solvable_name: vim
//
// A package matches when any solvable_name or solvable_arch value matches it,
// and its edition satisfies the version constraint when there is one.
type zypperLock struct {
	names, archs  []string
	matchType     string
	caseSensitive bool
	op, edition   string
}

type zypperLocks []zypperLock

func (l zypperLocks) holds(pkg Package) bool {
	for i := range l {
		if l[i].holds(pkg) {
			return true
		}
	}
	return false
}

// parseZypperLocks reads the store the way libzypp does: a paragraph per lock,
// ended by a line that holds nothing but whitespace. Only leading and trailing
// spaces and tabs are cut from a value, so a store saved with CRLF line ends
// carries the CR in every name and, as with zypper, holds nothing.
func parseZypperLocks(content string) zypperLocks {
	var out zypperLocks
	cur := newZypperLock()
	hasKind, isPackage, empty := false, false, true
	flush := func() {
		if !empty && (!hasKind || isPackage) && (len(cur.names) > 0 || len(cur.archs) > 0) {
			out = append(out, cur)
		}
		cur = newZypperLock()
		hasKind, isPackage, empty = false, false, true
	}

	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(value, " \t")
		empty = false
		switch key {
		case "solvable_name":
			cur.names = append(cur.names, value)
		case "solvable_arch":
			cur.archs = append(cur.archs, value)
		case "type":
			hasKind = true
			if value == "package" {
				isPackage = true
			}
		case "match_type":
			cur.matchType = value
		case "case_sensitive":
			switch value {
			case "on", "true", "1", "yes":
				cur.caseSensitive = true
			case "off", "false", "0", "no":
				cur.caseSensitive = false
			}
		case "version":
			cur.op, cur.edition = parseZypperLockVersion(value)
		}
	}
	flush()
	return out
}

// newZypperLock carries libzypp's defaults for an attribute a paragraph leaves
// out: zypper treats a lock with no match_type or case_sensitive as a case
// insensitive substring match.
func newZypperLock() zypperLock {
	return zypperLock{matchType: "substring"}
}

// parseZypperLockVersion splits `< 1.0` into its operator and edition.
func parseZypperLockVersion(value string) (op, edition string) {
	fields := strings.Fields(value)
	switch len(fields) {
	case 1:
		return "==", fields[0]
	case 2:
		switch fields[0] {
		case "=", "==", "eq":
			return "==", fields[1]
		case "!=", "ne":
			return "!=", fields[1]
		case "<", "lt":
			return "<", fields[1]
		case "<=", "le":
			return "<=", fields[1]
		case ">", "gt":
			return ">", fields[1]
		case ">=", "ge":
			return ">=", fields[1]
		}
	}
	return "", ""
}

func (l *zypperLock) holds(pkg Package) bool {
	matched := false
	for _, n := range l.names {
		if l.match(n, pkg.Name) {
			matched = true
			break
		}
	}
	if !matched {
		for _, a := range l.archs {
			if l.match(a, pkg.Arch) {
				matched = true
				break
			}
		}
	}
	if !matched {
		return false
	}
	if l.edition == "" {
		return true
	}
	return zypperLockPins(installedEVR(pkg), l.op, l.edition)
}

// zypperLockPins reports whether a version constrained lock holds the
// installed package at its version. zypper keeps a locked installed package,
// so the lock pins it when the installed edition satisfies the constraint. A
// `>` lock at the installed edition locks every newer one instead, which holds
// it as well. A lock that matches only some newer editions (`= 2.0` over an
// installed 1.0) keeps those out and leaves the package free to update.
func zypperLockPins(installed, op, edition string) bool {
	c := compareEVRMatch(installed, edition)
	switch op {
	case "==":
		return c == 0
	case "!=":
		// the installed edition is either locked, or the one that is not
		return true
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case ">":
		return c >= 0
	case ">=":
		return c >= 0
	}
	return false
}

func (l *zypperLock) match(pattern, value string) bool {
	if pattern == "" || value == "" {
		return false
	}
	switch l.matchType {
	case "exact":
		if l.caseSensitive {
			return pattern == value
		}
		return strings.EqualFold(pattern, value)
	case "glob":
		if !l.caseSensitive {
			pattern, value = strings.ToLower(pattern), strings.ToLower(value)
		}
		ok, err := path.Match(pattern, value)
		return err == nil && ok
	case "regex":
		if !l.caseSensitive {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		return err == nil && re.MatchString(value)
	case "words":
		if !l.caseSensitive {
			pattern, value = strings.ToLower(pattern), strings.ToLower(value)
		}
		return containsWord(value, pattern)
	default:
		// substring, and what libzypp does with a match_type it does not know
		if !l.caseSensitive {
			pattern, value = strings.ToLower(pattern), strings.ToLower(value)
		}
		return strings.Contains(value, pattern)
	}
}

// containsWord reports whether word occurs in s bounded by the ends of s or by
// characters that are not letters or digits: zypper's words lock `g03` holds
// g03-uni.
func containsWord(s, word string) bool {
	for start := 0; start <= len(s)-len(word); {
		i := strings.Index(s[start:], word)
		if i < 0 {
			return false
		}
		i += start
		end := i + len(word)
		if (i == 0 || !isAlnum(s[i-1])) && (end == len(s) || !isAlnum(s[end])) {
			return true
		}
		start = i + 1
	}
	return false
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// installedEVR is the package's epoch:version-release.
func installedEVR(pkg Package) string {
	if pkg.Epoch != "" && !strings.Contains(pkg.Version, ":") {
		return pkg.Epoch + ":" + pkg.Version
	}
	return pkg.Version
}

// compareEVRMatch orders two epoch:version-release strings the way libzypp
// matches an edition against a lock: a missing epoch is 0, and a release left
// out on either side matches any release.
func compareEVRMatch(a, b string) int {
	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	if ra == "" || rb == "" {
		return 0
	}
	return rpmvercmp(ra, rb)
}

func splitEVR(evr string) (epoch uint64, version, release string) {
	if i := strings.IndexByte(evr, ':'); i >= 0 {
		if n, err := strconv.ParseUint(evr[:i], 10, 64); err == nil {
			epoch = n
			evr = evr[i+1:]
		}
	}
	if i := strings.LastIndexByte(evr, '-'); i >= 0 {
		return epoch, evr[:i], evr[i+1:]
	}
	return epoch, evr, ""
}

// rpmvercmp is rpm's version segment comparison, including `~` (sorts before
// anything, even the end) and `^` (sorts after the end, before anything else).
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	isAlpha := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		if (i < len(a) && a[i] == '~') || (j < len(b) && b[j] == '~') {
			if i >= len(a) || a[i] != '~' {
				return 1
			}
			if j >= len(b) || b[j] != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if (i < len(a) && a[i] == '^') || (j < len(b) && b[j] == '^') {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if a[i] != '^' {
				return 1
			}
			if b[j] != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}

		si, sj := i, j
		numeric := isDigit(a[i])
		class := isAlpha
		if numeric {
			class = isDigit
		}
		for i < len(a) && class(a[i]) {
			i++
		}
		for j < len(b) && class(b[j]) {
			j++
		}
		sa, sb := a[si:i], b[sj:j]
		if sb == "" {
			// a numeric segment is newer than an alphabetic one
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			sa = strings.TrimLeft(sa, "0")
			sb = strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				if len(sa) < len(sb) {
					return -1
				}
				return 1
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
	}
	if i >= len(a) && j >= len(b) {
		return 0
	}
	if i >= len(a) {
		return -1
	}
	return 1
}
