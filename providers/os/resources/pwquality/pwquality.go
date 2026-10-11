// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package pwquality reads libpwquality's configuration the way the library
// does (src/settings.c): the drop-ins of <file>.d in file name order, then the
// file itself, the last assignment of a setting winning.
package pwquality

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
)

const (
	// DefaultFile is the configuration libpwquality reads unless pam_pwquality
	// is given conf=.
	DefaultFile = "/etc/security/pwquality.conf"
	// BaseFile is read instead of DefaultFile when DefaultFile does not exist.
	// Its drop-ins apply under the /etc ones of other names. libpwquality
	// added it after 1.4.5 (commit 447c6ae, "Support snippets in
	// /usr/lib/security").
	BaseFile = "/usr/lib/security/pwquality.conf"
)

// Setting types, as in libpwquality's s_map.
type kind int

const (
	kindInt kind = iota
	kindString
	kindFlag
)

var settingKinds = map[string]kind{
	"difok":            kindInt,
	"minlen":           kindInt,
	"dcredit":          kindInt,
	"ucredit":          kindInt,
	"lcredit":          kindInt,
	"ocredit":          kindInt,
	"minclass":         kindInt,
	"maxrepeat":        kindInt,
	"maxclassrepeat":   kindInt,
	"maxsequence":      kindInt,
	"gecoscheck":       kindInt,
	"dictcheck":        kindInt,
	"usercheck":        kindInt,
	"usersubstr":       kindInt,
	"enforcing":        kindInt,
	"badwords":         kindString,
	"dictpath":         kindString,
	"retry":            kindInt,
	"enforce_for_root": kindFlag,
	"local_users_only": kindFlag,
	"allowclasses":     kindString,
}

// Defaults are libpwquality's built-in values (pwqprivate.h) for the integer
// settings. dictcheck is 1 when the library is built with cracklib, which
// every distribution does.
var Defaults = map[string]int64{
	"difok":            1,
	"minlen":           8,
	"dcredit":          0,
	"ucredit":          0,
	"lcredit":          0,
	"ocredit":          0,
	"minclass":         0,
	"maxrepeat":        0,
	"maxclassrepeat":   0,
	"maxsequence":      0,
	"gecoscheck":       0,
	"dictcheck":        1,
	"usercheck":        1,
	"usersubstr":       0,
	"enforcing":        1,
	"retry":            1,
	"enforce_for_root": 0,
	"local_users_only": 0,
}

// LegacyDefaults are the defaults that differ before libpwquality 1.3.0
// (commit 2a41d82, "Change the default settings"), as on RHEL 7, Amazon
// Linux 2 and SLES 12.
var LegacyDefaults = map[string]int64{
	"difok":   5,
	"minlen":  9,
	"dcredit": 1,
	"ucredit": 1,
	"lcredit": 1,
	"ocredit": 1,
}

const (
	// baseMinLength is the smallest minlen libpwquality accepts; a lower value
	// is raised to it (PWQ_BASE_MIN_LENGTH).
	baseMinLength = 6
	// numClasses caps minclass (PWQ_NUM_CLASSES).
	numClasses = 4
)

// Settings holds the settings assigned so far, by lower-case name. A flag
// such as enforce_for_root has an empty value.
type Settings map[string]string

// Error reports a line libpwquality rejects. The library stops reading at
// that line: the rest of the file and every later file are ignored.
type Error struct {
	File string
	Line int
	Name string
	Err  string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s:%d: %s: %s", e.File, e.Line, e.Name, e.Err)
}

// Apply parses one configuration file into s, as read_config_file does: a #
// starts a comment anywhere on a line, the name ends at whitespace or =, and
// names are matched without regard to case. It returns an *Error for an
// unknown setting or a malformed integer, after applying the lines before it.
func (s Settings) Apply(file string, r io.Reader) error {
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		name, value := splitLine(line)
		if err := s.set(name, value); err != "" {
			return &Error{File: file, Line: lineNo, Name: name, Err: err}
		}
	}
	return scanner.Err()
}

// ApplyOption applies one pam_pwquality module argument, such as minlen=14 or
// enforce_for_root (pwquality_set_option). It reports false for an argument
// that is not a setting.
func (s Settings) ApplyOption(option string) bool {
	name, value, _ := strings.Cut(option, "=")
	return s.set(name, value) == ""
}

// splitLine separates a name from its value as read_config_file does: the name
// ends at the first whitespace or =, then whitespace and a single = are
// skipped.
func splitLine(line string) (string, string) {
	end := strings.IndexFunc(line, func(r rune) bool { return r == '=' || isSpace(r) })
	if end < 0 {
		return line, ""
	}
	name := line[:end]
	eq := line[end] == '='
	rest := line[end+1:]
	for rest != "" {
		c := rest[0]
		if c == '=' && !eq {
			eq = true
		} else if !isSpace(rune(c)) {
			break
		}
		rest = rest[1:]
	}
	return name, rest
}

func isSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

func (s Settings) set(name, value string) string {
	key := strings.ToLower(name)
	k, ok := settingKinds[key]
	if !ok {
		return "unknown setting"
	}
	switch k {
	case kindInt:
		v, err := strconv.ParseInt(value, 10, 32)
		if err != nil || v == 1<<31-1 || v == -(1<<31) {
			return "not an integer"
		}
		s[key] = strconv.FormatInt(v, 10)
	case kindString:
		s[key] = value
	case kindFlag:
		s[key] = ""
	}
	return ""
}

// Int returns an integer setting as libpwquality applies it: the value set,
// raised or capped where the library does, or the default. A flag is 1 when
// set. legacy selects the defaults of libpwquality before 1.3.0.
func (s Settings) Int(name string, legacy bool) int64 {
	v, ok := s[name]
	if !ok {
		if d, ok := LegacyDefaults[name]; ok && legacy {
			return d
		}
		return Defaults[name]
	}
	if settingKinds[name] == kindFlag {
		return 1
	}
	i, _ := strconv.ParseInt(v, 10, 64)
	switch name {
	case "minlen":
		if i < baseMinLength {
			i = baseMinLength
		}
	case "minclass":
		if i > numClasses {
			i = numClasses
		}
	}
	return i
}

// Clone copies the settings, so PAM arguments can be applied on top of the
// configuration files.
func (s Settings) Clone() Settings {
	res := make(Settings, len(s))
	for k, v := range s {
		res[k] = v
	}
	return res
}

// IsDropIn reports whether libpwquality reads a file of this name from a .d
// directory (filter_conf): the first ".conf" in the name ends it.
func IsDropIn(name string) bool {
	i := strings.Index(name, ".conf")
	return i >= 0 && i+len(".conf") == len(name)
}

// Files lists the files libpwquality reads for the configuration file cfg, in
// order. etcDropIns are the names in cfg + ".d". When cfg is DefaultFile,
// mainExists says whether it exists (otherwise BaseFile is read in its place)
// and baseDropIns are the names in BaseFile + ".d"; an /etc drop-in hides a
// base drop-in of the same name. withDropIns is false for libpwquality before
// 1.3.0, which reads cfg alone.
func Files(cfg string, mainExists bool, etcDropIns, baseDropIns []string, withDropIns bool) []string {
	main := cfg
	if cfg == DefaultFile && !mainExists {
		main = BaseFile
	}
	if !withDropIns {
		return []string{main}
	}

	dir := map[string]string{}
	if cfg == DefaultFile {
		for _, n := range baseDropIns {
			if IsDropIn(n) {
				dir[n] = BaseFile + ".d"
			}
		}
	}
	for _, n := range etcDropIns {
		if IsDropIn(n) {
			dir[n] = cfg + ".d"
		}
	}
	names := make([]string, 0, len(dir))
	for n := range dir {
		names = append(names, n)
	}
	sort.Strings(names)

	res := make([]string, 0, len(names)+1)
	for _, n := range names {
		res = append(res, path.Join(dir[n], n))
	}
	return append(res, main)
}

// IsLegacy reports whether a libpwquality version is older than 1.3.0, which
// read no <file>.d drop-ins (commit a402819) and had other defaults (commit
// 2a41d82). An unparsable version is taken as current.
func IsLegacy(version string) bool {
	// strip an epoch and the release: 1:1.4.4-1, 1.2.3-5.el7
	if _, v, ok := strings.Cut(version, ":"); ok {
		version = v
	}
	version, _, _ = strings.Cut(version, "-")
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return major < 1 || major == 1 && minor < 3
}
