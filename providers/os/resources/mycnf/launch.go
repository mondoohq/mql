// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mycnf

import (
	"path"
	"slices"
	"strings"
)

// ServerLaunch is what a server's command line says about its configuration:
// which option files it reads and which options it sets itself. The command
// line is the last word on both. A drop-in that starts mysqld with
// --defaults-file=/etc/mysql/alt.cnf makes the server ignore /etc/mysql/my.cnf
// altogether, and a --bind-address on the command line overrides whatever the
// option files say.
type ServerLaunch struct {
	// Binary is the base name of the program, "mysqld" or "mariadbd".
	Binary string
	// NoDefaults reports --no-defaults: the server reads no option file.
	NoDefaults bool
	// DefaultsFile is the --defaults-file argument, the only option file the
	// server reads when it is set.
	DefaultsFile string
	// ExtraFile is the --defaults-extra-file argument, read after the global
	// option files.
	ExtraFile string
	// GroupSuffix is the --defaults-group-suffix argument. The server then
	// also reads every group it reads with this suffix appended, as in
	// [mysqld_eu] for a suffix of "_eu".
	GroupSuffix string
	// Options are the options given on the command line, in order, with the
	// same normalization as options read from a file.
	Options []Option
}

// IsServerBinary reports whether a program name is a MySQL or MariaDB server
// binary. Wrappers such as mysqld_safe are not: they take options of their
// own, and the server they start shows up as a process of its own.
func IsServerBinary(name string) bool {
	switch path.Base(name) {
	case "mysqld", "mariadbd":
		return true
	}
	return false
}

// ParseServerArgs reads a server command line, argv[0] included, the way the
// server does. It reports false when argv does not start a server binary.
//
// The option file arguments count only at the front of the command line,
// where the server looks for them (get_defaults_options in my_default.c stops
// at the first argument that is not one of them); anywhere else the server
// rejects them as unknown options and does not start. They must be written
// with "=". The remaining long options are the server's own settings and
// override the option files. Short options and positional arguments carry
// nothing this package reports and are skipped.
func ParseServerArgs(argv []string) (ServerLaunch, bool) {
	if len(argv) == 0 || !IsServerBinary(argv[0]) {
		return ServerLaunch{}, false
	}
	launch := ServerLaunch{Binary: path.Base(argv[0])}

	rest := argv[1:]
	for len(rest) > 0 {
		arg := rest[0]
		if arg == "--no-defaults" {
			launch.NoDefaults = true
		} else if v, ok := strings.CutPrefix(arg, "--defaults-file="); ok {
			launch.DefaultsFile = v
		} else if v, ok := strings.CutPrefix(arg, "--defaults-extra-file="); ok {
			launch.ExtraFile = v
		} else if v, ok := strings.CutPrefix(arg, "--defaults-group-suffix="); ok {
			launch.GroupSuffix = v
		} else {
			break
		}
		rest = rest[1:]
	}
	if launch.NoDefaults {
		// --no-defaults reads no file at all; the server refuses to start
		// when it is combined with a file argument, so none applies.
		launch.DefaultsFile, launch.ExtraFile = "", ""
	}

	for i, arg := range rest {
		if arg == "--" {
			break
		}
		body, ok := strings.CutPrefix(arg, "--")
		if !ok || body == "" {
			continue
		}
		// Values on a command line are not quoted the way they are in a
		// file: the shell or systemd has already removed the quotes, and a
		// "#" is part of the value.
		name, value, hasValue := strings.Cut(body, "=")
		normalized, loose := NormalizeName(name)
		if normalized == "" {
			continue
		}
		opt := Option{Name: normalized, Value: value, Loose: loose, Bare: !hasValue, Line: i + 1}
		if target, resolved, ok := resolveBooleanPrefix(normalized, value, hasValue); ok {
			opt = Option{Name: target, Value: resolved, Loose: loose, Line: i + 1}
		}
		launch.Options = append(launch.Options, opt)
	}
	return launch, true
}

// suseHelperUser is the account mysql-systemd-helper starts the server as.
const suseHelperUser = "mysql"

// ParseSuseHelperArgs reads the ExecStart= of SUSE's MariaDB units,
// `/usr/libexec/mysql/mysql-systemd-helper start [instance]` (under
// /usr/lib/mysql on older releases). The helper execs the server as
//
//	/usr/sbin/mysqld --defaults-file=/etc/my<instance>.cnf --user=mysql --socket=...
//
// so the server reads that one file and never the service account's
// ~/.my.cnf. The --socket the helper adds is left out: it comes from what
// my_print_defaults reports for [mysqld] at start time. It reports false for
// any other command line.
func ParseSuseHelperArgs(argv []string) (ServerLaunch, bool) {
	if len(argv) < 2 || path.Base(argv[0]) != "mysql-systemd-helper" || argv[1] != "start" {
		return ServerLaunch{}, false
	}
	instance := ""
	if len(argv) > 2 {
		instance = argv[2]
	}
	return ServerLaunch{
		Binary:       "mysqld",
		DefaultsFile: "/etc/my" + instance + ".cnf",
		Options:      []Option{{Name: "user", Value: suseHelperUser, Line: 1}},
	}, true
}

// WithGroupSuffix extends a list of option groups with the suffixed form of
// each, which a server started with --defaults-group-suffix reads as well.
func WithGroupSuffix(groups []string, suffix string) []string {
	if suffix == "" {
		return groups
	}
	out := make([]string, 0, 2*len(groups))
	out = append(out, groups...)
	for _, g := range groups {
		out = append(out, g+suffix)
	}
	return out
}

// argsGroup is the group MergeWithArgs files command line options under.
const argsGroup = "\x00command-line"

// MergeWithArgs is Merge with the options given on a server's command line
// applied last. The server reads its command line after every option file, so
// each of those options wins over a file's, except that a cumulative option
// (plugin_load_add) adds to what the files listed.
func MergeWithArgs(c *Conf, args []Option, groups ...string) map[string]string {
	if len(args) == 0 {
		return Merge(c, groups...)
	}
	// Command line options carry no group. They are merged under a name no
	// group header can produce (the parser never yields a NUL), so no
	// option read from a file can be mistaken for one of them.
	all := &Conf{Options: make([]Option, 0, len(c.Options)+len(args))}
	all.Options = append(all.Options, c.Options...)
	for _, opt := range args {
		opt.Section = argsGroup
		all.Options = append(all.Options, opt)
	}
	return Merge(all, append(slices.Clone(groups), argsGroup)...)
}

// Append adds the options, groups and files of another parse after this
// one's, as the server reads a --defaults-extra-file after the files it reads
// by default.
func (c *Conf) Append(other *Conf) {
	if other == nil {
		return
	}
	c.Options = append(c.Options, other.Options...)
	for _, f := range other.Files {
		if !contains(c.Files, f) {
			c.Files = append(c.Files, f)
		}
	}
	c.Includes = append(c.Includes, other.Includes...)
	for _, g := range other.groups {
		if !contains(c.groups, g) {
			c.groups = append(c.groups, g)
		}
		if c.groupFiles == nil {
			c.groupFiles = map[string][]string{}
		}
		for _, f := range other.groupFiles[g] {
			if !contains(c.groupFiles[g], f) {
				c.groupFiles[g] = append(c.groupFiles[g], f)
			}
		}
	}
}
