// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path"
	"sort"

	"github.com/spf13/afero"
)

// systemdConfigSearchDirs lists the directories systemd reads a daemon's
// configuration from (journald.conf, coredump.conf, ...), highest priority
// first. It matches the CONF_PATHS used by
// config_parse_standard_file_with_dropins() in systemd's conf-parser.c.
var systemdConfigSearchDirs = []string{
	"/etc/systemd",
	"/run/systemd",
	"/usr/local/lib/systemd",
	"/usr/lib/systemd",
}

// findSystemdMainConfig returns the main configuration file systemd uses for
// the daemon config called name (e.g. "coredump.conf"): the first one that
// exists in systemdConfigSearchDirs. systemd reads only that one file, so a
// vendor copy under /usr/lib is ignored once /etc has one. It returns "" when
// no directory has the file, or when the first one found is a symlink to
// /dev/null, which masks the lower-priority copies without contributing.
func findSystemdMainConfig(fs afero.Fs, name string) (string, error) {
	for _, dir := range systemdConfigSearchDirs {
		candidate := path.Join(dir, name)
		if isSymlinkToDevNull(fs, candidate) {
			return "", nil
		}
		exists, err := afero.Exists(fs, candidate)
		if err != nil {
			return "", err
		}
		if exists {
			return candidate, nil
		}
	}
	return "", nil
}

// findSystemdConfigDropins returns the drop-in files systemd applies after the
// main configuration file called name, in the order it applies them: every
// <dir>/<name>.d/*.conf across systemdConfigSearchDirs, sorted by file name
// regardless of directory. A file name found in a higher-priority directory
// masks the same name in the lower ones, and a drop-in that is a symlink to
// /dev/null masks without contributing, so it is left out of the result.
func findSystemdConfigDropins(fs afero.Fs, name string) ([]string, error) {
	type dropin struct {
		basename string
		path     string
		priority int
	}
	byName := map[string]dropin{}

	for priority, dir := range systemdConfigSearchDirs {
		matches, err := afero.Glob(fs, path.Join(dir, name+".d", "*.conf"))
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			base := path.Base(match)
			if selected, ok := byName[base]; ok && selected.priority < priority {
				continue
			}
			byName[base] = dropin{basename: base, path: match, priority: priority}
		}
	}

	dropins := make([]dropin, 0, len(byName))
	for _, d := range byName {
		if isSymlinkToDevNull(fs, d.path) {
			continue
		}
		dropins = append(dropins, d)
	}
	sort.Slice(dropins, func(i, j int) bool {
		return dropins[i].basename < dropins[j].basename
	})

	paths := make([]string, len(dropins))
	for i := range dropins {
		paths[i] = dropins[i].path
	}
	return paths, nil
}

// isSystemdConfigMainPath reports whether p is where systemd looks for the
// main configuration file called name.
func isSystemdConfigMainPath(p string, name string) bool {
	for _, dir := range systemdConfigSearchDirs {
		if p == path.Join(dir, name) {
			return true
		}
	}
	return false
}

// isSymlinkToDevNull reports whether p is a symlink to /dev/null, which
// systemd treats as masking the file. Filesystems that cannot read links
// report false.
func isSymlinkToDevNull(fs afero.Fs, p string) bool {
	lr, ok := fs.(afero.LinkReader)
	if !ok {
		return false
	}
	target, err := lr.ReadlinkIfPossible(p)
	if err != nil {
		return false
	}
	return target == "/dev/null"
}
