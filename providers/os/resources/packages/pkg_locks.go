// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"path"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Lock files are read rather than the tools being asked, so a held package is
// reported the same way on a running host, a container image and a mounted
// filesystem. The commands (`dnf versionlock list`, `zypper locks`) only print
// what these files already contain, and they cannot run on an image at all.

// The RPM family's lock stores, newest first.
//
// On RHEL 9 and its rebuilds the yum paths are symlinks to the dnf ones, so
// probing rather than gating on a platform version resolves both with one read
// and stays correct on distributions this list has never heard of.
const dnf5VersionlockPath = "/etc/dnf/versionlock.toml" // dnf5: Fedora 41+

// versionlockPlugins are the dnf4 (RHEL 8 to 10, Fedora <= 40) and yum (RHEL
// 7, Amazon Linux 2) versionlock plugins: the plugin configuration, and the
// store it reads unless the configuration names another with `locklist`.
//
// main is the package manager's own configuration, whose `plugins` option
// turns every plugin off. dnf loads plugins unless it says otherwise; yum
// loads none unless it says `plugins=1`, which every yum.conf a distribution
// ships does.
var versionlockPlugins = []struct {
	conf, list, main string
	pluginsByDefault bool
}{
	{"/etc/dnf/plugins/versionlock.conf", "/etc/dnf/plugins/versionlock.list", "/etc/dnf/dnf.conf", true},
	{"/etc/yum/pluginconf.d/versionlock.conf", "/etc/yum/pluginconf.d/versionlock.list", "/etc/yum.conf", false},
}

// lockedNames is the set of package names a lock store holds. A nil or empty
// set means nothing is locked, which is the normal state of most hosts.
type lockedNames map[string]struct{}

// lockSet reports whether a lock store holds an installed package.
type lockSet interface {
	holds(pkg Package) bool
}

// holds matches a versionlock store on the name alone, see
// parseVersionlockTOML.
func (l lockedNames) holds(pkg Package) bool {
	return l.has(pkg.Name)
}

func (l lockedNames) has(name string) bool {
	if len(l) == 0 || name == "" {
		return false
	}
	if _, ok := l[name]; ok {
		return true
	}
	// A lock may be written as a glob, e.g. `kernel*`.
	for pattern := range l {
		if !strings.ContainsAny(pattern, "*?[") {
			continue
		}
		if ok, err := path.Match(pattern, name); err == nil && ok {
			return true
		}
	}
	return false
}

// readVersionlock returns the package names locked on an RPM-family host. A
// missing store is the common case and is not an error: it means the
// versionlock plugin is not installed, so nothing is locked. A store that
// exists but cannot be read (a 0600 file and a non-root scan) is an error:
// nothing is known about the locks it holds.
func readVersionlock(fs afero.Fs) (lockedNames, error) {
	raw, err := readLockStore(fs, dnf5VersionlockPath)
	if err != nil {
		return nil, err
	}
	if raw != nil {
		return parseVersionlockTOML(raw), nil
	}

	for _, p := range versionlockPlugins {
		list := p.list
		conf, err := readLockStore(fs, p.conf)
		if err != nil {
			return nil, err
		}
		if conf != nil {
			mainConf, err := readLockStore(fs, p.main)
			if err != nil {
				return nil, err
			}
			if mainConf != nil && !parsePluginsEnabled(string(mainConf), p.pluginsByDefault) {
				// the package manager loads no plugins: its locks hold nothing
				return nil, nil
			}

			enabled, locklist := parseVersionlockConf(string(conf))
			if !enabled {
				// the plugin is installed and turned off: its locks hold nothing
				return nil, nil
			}
			if locklist != "" {
				list = locklist
			}
		}

		raw, err := readLockStore(fs, list)
		if err != nil {
			return nil, err
		}
		if raw != nil {
			return parseVersionlockList(string(raw)), nil
		}
		if conf != nil {
			// the plugin is installed and enabled and has no store yet: it
			// reads no other plugin's store, so nothing is locked
			return nil, nil
		}
	}
	return nil, nil
}

// readLockStore reads a lock store or plugin configuration. A file that does
// not exist returns nil and no error.
func readLockStore(fs afero.Fs, p string) ([]byte, error) {
	f, err := fs.Open(p)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		raw = []byte{}
	}
	return raw, nil
}

// parseVersionlockConf reads the [main] section of the versionlock plugin's
// configuration as AlmaLinux 9 ships it:
//
//	[main]
//	enabled = 1
//	locklist = /etc/dnf/plugins/versionlock.list
//
// A plugin is enabled unless `enabled` says otherwise. locklist is "" when
// the configuration names no store.
func parseVersionlockConf(content string) (enabled bool, locklist string) {
	enabled = true
	inMain := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
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
		case "enabled":
			switch strings.ToLower(value) {
			case "0", "false", "no", "off":
				enabled = false
			default:
				enabled = true
			}
		case "locklist":
			locklist = value
		}
	}
	return enabled, locklist
}

// parsePluginsEnabled reads the `plugins` option of a dnf.conf or yum.conf
// [main] section. def is what the package manager assumes when the option is
// not set.
func parsePluginsEnabled(content string, def bool) bool {
	enabled := def
	inMain := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
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
		if !found || strings.TrimSpace(key) != "plugins" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "0", "false", "no", "off":
			enabled = false
		case "1", "true", "yes", "on":
			enabled = true
		}
	}
	return enabled
}

// parseVersionlockList reads the flat store dnf4 and yum write, one entry per
// line with `#` comments:
//
//	# Added lock on Sun Aug 23 10:39:39 2026
//	vim-minimal-2:8.2.2637-26.el9_8.4.*
//
// The two write the epoch in different places. dnf4 puts it after the name, as
// above; yum puts it in front of the whole entry:
//
//	2:vim-minimal-9.0.2153-1.amzn2.0.9.*
//
// Both are handled, because both were read off a real host: the first from
// AlmaLinux 9, the second from Amazon Linux 2.
func parseVersionlockList(content string) lockedNames {
	out := lockedNames{}
	for _, line := range strings.Split(content, "\n") {
		entry := strings.TrimSpace(line)
		if idx := strings.IndexByte(entry, '#'); idx >= 0 {
			entry = strings.TrimSpace(entry[:idx])
		}
		// `!name-version` is an exclude: it keeps that version out and
		// holds nothing
		if entry == "" || entry[0] == '!' {
			continue
		}
		if name := versionlockEntryName(entry); name != "" {
			out[name] = struct{}{}
		}
	}
	return out
}

// versionlockEntryName recovers the package name from a versionlock entry.
//
// An entry is a NEVRA with globs: `name-[epoch:]version-release.arch`. Both the
// name and the release contain hyphens, so neither the first nor the last one
// separates the name. The version and release are the last two hyphen-separated
// components, so removing them leaves the name whatever it contains:
//
//	vim-minimal-2:8.2.2637-26.el9_8.4.*   -> vim-minimal
//	java-1.8.0-openjdk-1:1.8.0.442-2.el9  -> java-1.8.0-openjdk
//
// The second is why a left-to-right scan for "hyphen followed by a digit" does
// not work: that name begins with one. An entry with fewer than two hyphens
// names no version and is returned whole, so a glob such as `kernel*` survives
// for `has` to match as a pattern.
func versionlockEntryName(entry string) string {
	// yum writes a leading `<epoch>:`; strip it before splitting.
	if idx := strings.IndexByte(entry, ':'); idx > 0 && isAllDigits(entry[:idx]) {
		entry = entry[idx+1:]
	}

	// drop release.arch, then epoch:version
	rest, _, found := cutLast(entry, '-')
	if !found {
		return entry
	}
	name, _, found := cutLast(rest, '-')
	if !found {
		return entry
	}
	return name
}

// cutLast splits s around the last instance of sep.
func cutLast(s string, sep byte) (before, after string, found bool) {
	i := strings.LastIndexByte(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+1:], true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// versionlockTOML is the store dnf5 writes, which is a different format rather
// than a different path:
//
//	version = "1.0"
//
//	[[packages]]
//	name = "vim-minimal"
//	comment = "Added by 'versionlock add' command on 2026-08-23"
//
//	[[packages.conditions]]
//	key = "evr"
//	comparator = "="
//	value = "2:9.2.530-1.fc44"
//
// Only the name is needed: a lock pinned to a specific version still means the
// installed package is held. The exception is the entry `dnf versionlock
// exclude` writes, whose condition is `!=`: it keeps one version out and
// leaves the package free to update.
type versionlockTOML struct {
	Packages []struct {
		Name       string `toml:"name"`
		Conditions []struct {
			Comparator string `toml:"comparator"`
		} `toml:"conditions"`
	} `toml:"packages"`
}

func parseVersionlockTOML(raw []byte) lockedNames {
	var doc versionlockTOML
	if err := toml.Unmarshal(raw, &doc); err != nil {
		// A store that does not parse is not an empty store. Report it and
		// return nothing rather than claiming the host has no locks.
		log.Warn().Err(err).Msg("could not parse the dnf versionlock store, locks will not be reported")
		return nil
	}

	out := lockedNames{}
	for _, pkg := range doc.Packages {
		if pkg.Name == "" {
			continue
		}
		exclude := false
		for _, c := range pkg.Conditions {
			if c.Comparator == "!=" || c.Comparator == "<>" {
				exclude = true
			}
		}
		if !exclude {
			out[pkg.Name] = struct{}{}
		}
	}
	return out
}

// markPinned flags the packages a lock store holds. Called once per listing,
// so the store is read once rather than once per package. readErr is why the
// store could not be read: with StructuredErrors every package's pinned is
// that error; v13 reported nothing pinned.
func markPinned(pkgs []Package, locks lockSet, readErr error) []Package {
	if readErr != nil {
		if !plugin.StructuredErrors() {
			log.Warn().Err(readErr).Msg("could not read the package lock store, packages report not pinned")
			return pkgs
		}
		if errors.Is(readErr, iofs.ErrPermission) {
			readErr = llx.Forbidden(fmt.Errorf("cannot read the package lock store: %w", readErr))
		} else {
			readErr = fmt.Errorf("cannot read the package lock store: %w", readErr)
		}
		for i := range pkgs {
			pkgs[i].PinnedErr = readErr
		}
		return pkgs
	}
	if locks == nil {
		return pkgs
	}
	for i := range pkgs {
		if locks.holds(pkgs[i]) {
			pkgs[i].Pinned = true
		}
	}
	return pkgs
}
