// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"bufio"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// SysctlDirs are the sysctl.d directories, highest priority first. systemd
// and procps read the same set: a file in an earlier directory hides a file
// of the same name in a later one. /lib/sysctl.d is read on split-/usr
// systems; on merged-/usr systems it is /usr/lib/sysctl.d, and every file in
// it is hidden by its own copy there.
var SysctlDirs = []string{
	"/etc/sysctl.d",
	"/run/sysctl.d",
	"/usr/local/lib/sysctl.d",
	"/usr/lib/sysctl.d",
	"/lib/sysctl.d",
}

// SysctlConf is the classic single configuration file. systemd-sysctl does
// not read it; distributions link it in as /etc/sysctl.d/99-sysctl.conf.
// procps `sysctl --system` reads it after every sysctl.d file.
const SysctlConf = "/etc/sysctl.conf"

// SystemdSysctlBinaries are the locations of systemd-sysctl, the program that
// applies sysctl.d at boot on a systemd host.
var SystemdSysctlBinaries = []string{
	"/usr/lib/systemd/systemd-sysctl",
	"/lib/systemd/systemd-sysctl",
}

// SysctlFeatures are the parts of the sysctl.d syntax a systemd-sysctl
// understands. Older versions read the same files with fewer rules.
type SysctlFeatures struct {
	// IgnoreErrorsPrefix is set when a leading "-" on an assignment means
	// errors are ignored (systemd 243). Before that the "-" is part of the
	// key, which names no parameter.
	IgnoreErrorsPrefix bool
	// Globs is set when a key may be a glob and a `-key` line with no value
	// excludes the key from globs (systemd 245). Before that a glob is a
	// literal key that names no parameter, and a `-key` line is not an
	// assignment.
	Globs bool
}

// ModernSysctlFeatures is the syntax of systemd 245 and later.
var ModernSysctlFeatures = SysctlFeatures{IgnoreErrorsPrefix: true, Globs: true}

var (
	systemdVersionRegex = regexp.MustCompile(`^systemd (\d+)\b`)
	// RHEL 8's systemd 239 backports the "-" prefix from 243 in release
	// 239-57.el8 ("sysctl: if options are prefixed with "-" ignore write
	// errors", rhbz#2037807); globs were not backported.
	rhel8SystemdReleaseRegex = regexp.MustCompile(`\(239-(\d+)\.el8`)
)

// ParseSystemdSysctlFeatures returns the sysctl.d syntax of the systemd-sysctl
// whose `--version` output is out, and false when out does not name a
// systemd version.
func ParseSystemdSysctlFeatures(out string) (SysctlFeatures, bool) {
	firstLine, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	m := systemdVersionRegex.FindStringSubmatch(firstLine)
	if m == nil {
		return SysctlFeatures{}, false
	}
	version, err := strconv.Atoi(m[1])
	if err != nil {
		return SysctlFeatures{}, false
	}

	features := SysctlFeatures{
		IgnoreErrorsPrefix: version >= 243,
		Globs:              version >= 245,
	}
	if r := rhel8SystemdReleaseRegex.FindStringSubmatch(firstLine); r != nil {
		if release, err := strconv.Atoi(r[1]); err == nil && release >= 57 {
			features.IgnoreErrorsPrefix = true
		}
	}
	return features, true
}

// SysctlAssignment is one `key = value` line of a sysctl configuration file.
type SysctlAssignment struct {
	// Key as written, without a leading "-" that marks IgnoreErrors
	Key string
	// Name is Key in the dotted form `sysctl -a` prints. It may hold glob
	// characters.
	Name  string
	Value string
	File  string
	Line  int
	// IgnoreErrors is set by a leading "-": a failure to apply the line is
	// not an error.
	IgnoreErrors bool
}

// SysctlConfig holds every assignment from the files a host applies, in the
// order they are applied.
type SysctlConfig struct {
	Assignments []SysctlAssignment
	// Exclusions are the names listed on a `-name` line with no value. They
	// are excluded from every glob assignment.
	Exclusions map[string]bool
	// Features is the syntax the files are read with.
	Features SysctlFeatures
}

// NewSysctlConfig returns an empty configuration read with the syntax of
// current systemd and procps.
func NewSysctlConfig() *SysctlConfig {
	return &SysctlConfig{
		Exclusions: map[string]bool{},
		Features:   ModernSysctlFeatures,
	}
}

// IsGlob reports whether name is a glob that applies to every parameter it
// matches, rather than a literal name.
func (c *SysctlConfig) IsGlob(name string) bool {
	return c.Features.Globs && IsSysctlGlob(name)
}

// Parse appends the assignments in r, read from file, to the configuration.
//
// The format is the one systemd-sysctl and procps share: blank lines and
// lines starting with `#` or `;` are comments, a line is split on its first
// `=`, and key and value are trimmed. A leading `-` on an assignment means
// errors are ignored. A `-key` line with no `=` excludes the key from globs.
// Any other line without `=` is not an assignment and is skipped, as both
// tools do. Features without support for the "-" prefix or globs keep the
// "-" as part of the key and read no exclusions.
func (c *SysctlConfig) Parse(r io.Reader, file string) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || text[0] == '#' || text[0] == ';' {
			continue
		}

		rawKey, value, found := strings.Cut(text, "=")
		rawKey = strings.TrimSpace(rawKey)
		dashed := strings.HasPrefix(rawKey, "-")
		unprefixed := strings.TrimSpace(strings.TrimPrefix(rawKey, "-"))

		if !found {
			if dashed && unprefixed != "" && c.Features.Globs {
				c.Exclusions[NormalizeSysctlName(unprefixed)] = true
			}
			continue
		}

		ignoreErrors := dashed && c.Features.IgnoreErrorsPrefix
		key := rawKey
		if ignoreErrors {
			key = unprefixed
		}
		if key == "" {
			continue
		}

		a := SysctlAssignment{
			Key:          key,
			Name:         NormalizeSysctlName(key),
			Value:        NormalizeSysctlValue(value),
			File:         file,
			Line:         line,
			IgnoreErrors: ignoreErrors,
		}
		c.Assignments = append(c.Assignments, a)
	}
	return scanner.Err()
}

// Lookup returns the assignments that apply to the parameter name, in the
// order they are applied, and the index of the one that takes effect, or -1
// when none does.
//
// An explicit assignment of name always takes effect over a glob, whichever
// comes first, and among explicit assignments the last one wins. Without an
// explicit assignment the last matching glob wins, unless an exclusion line
// names the parameter. Glob matches are still returned when they do not take
// effect, so a caller can see every line that names the parameter.
//
// When name is itself a glob, it is a pattern no live parameter matched and
// only the assignments of that exact pattern apply.
func (c *SysctlConfig) Lookup(name string) ([]SysctlAssignment, int) {
	name = NormalizeSysctlName(name)
	pattern := c.IsGlob(name)

	var res []SysctlAssignment
	effective, lastGlob := -1, -1
	for _, a := range c.Assignments {
		switch {
		case a.Name == name:
			res = append(res, a)
			effective = len(res) - 1
		case !pattern && c.IsGlob(a.Name) && matchSysctlGlob(a.Name, name):
			res = append(res, a)
			lastGlob = len(res) - 1
		}
	}

	if effective >= 0 {
		return res, effective
	}
	if lastGlob >= 0 && !c.Exclusions[name] {
		return res, lastGlob
	}
	return res, -1
}

// Names returns the names of every explicit assignment and the patterns of
// every glob assignment, each once, in order of first appearance.
func (c *SysctlConfig) Names() []string {
	seen := map[string]bool{}
	var res []string
	for _, a := range c.Assignments {
		if seen[a.Name] {
			continue
		}
		seen[a.Name] = true
		res = append(res, a.Name)
	}
	return res
}

// MatchSysctlGlob reports whether the parameter name matches the glob
// pattern. Both are in dotted form.
func MatchSysctlGlob(pattern, name string) bool {
	return matchSysctlGlob(NormalizeSysctlName(pattern), NormalizeSysctlName(name))
}

// matchSysctlGlob matches like fnmatch with FNM_PATHNAME on the /proc/sys
// path, which is how systemd and procps match: a wildcard stays within one
// path component, so `net.ipv4.conf.*.rp_filter` matches the interface
// `enp3s0/200` (the VLAN `enp3s0.200`) but never spans two components.
func matchSysctlGlob(pattern, name string) bool {
	p := strings.ReplaceAll(sysctlPathForm(pattern), "[!", "[^")
	ok, err := path.Match(p, sysctlPathForm(name))
	return err == nil && ok
}

// IsSysctlGlob reports whether a sysctl name is a glob pattern.
func IsSysctlGlob(name string) bool {
	return strings.ContainsAny(name, "*?[")
}

// NormalizeSysctlName returns a sysctl name in the dotted form `sysctl -a`
// prints. The first separator decides how the name is read: after a dot,
// dots separate components and a slash is part of one (`enp3s0/200` for the
// interface `enp3s0.200`); after a slash it is the other way round. A name
// written with slashes therefore has its dots and slashes swapped.
func NormalizeSysctlName(key string) string {
	key = strings.TrimLeft(strings.TrimSpace(key), "/")
	i := strings.IndexAny(key, "./")
	if i < 0 || key[i] == '.' {
		return key
	}
	return swapSysctlSeparators(key)
}

// SysctlPath returns the path under /proc/sys of a parameter name in dotted
// form.
func SysctlPath(name string) string {
	return sysctlPath + sysctlPathForm(NormalizeSysctlName(name))
}

// sysctlPathForm turns a dotted name into its path under /proc/sys.
func sysctlPathForm(name string) string {
	return swapSysctlSeparators(name)
}

func swapSysctlSeparators(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '.':
			return '/'
		case '/':
			return '.'
		}
		return r
	}, s)
}

// NormalizeSysctlValue trims a value and collapses each run of whitespace to
// one space. The kernel prints the parts of a value such as
// net.ipv4.ip_local_port_range separated by a tab, and configuration files
// separate them by spaces; both normalize to the same string.
func NormalizeSysctlValue(v string) string {
	return strings.Join(strings.Fields(v), " ")
}
