// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"io"
	"path"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// Lock files are read rather than the tools being asked, so a held package is
// reported the same way on a running host, a container image and a mounted
// filesystem. The commands (`dnf versionlock list`, `zypper locks`) only print
// what these files already contain, and they cannot run on an image at all.

// versionlockPaths are the stores the RPM family writes locks to, newest first.
//
// On RHEL 9 and its rebuilds the yum path is a symlink to the dnf one, so
// probing rather than gating on a platform version resolves both with one read
// and stays correct on distributions this list has never heard of.
var versionlockPaths = []string{
	"/etc/dnf/versionlock.toml",              // dnf5: RHEL 10, Fedora 41+
	"/etc/dnf/plugins/versionlock.list",      // dnf4: RHEL 8/9, Fedora <= 40
	"/etc/yum/pluginconf.d/versionlock.list", // yum: RHEL 7, Amazon Linux 2
}

// zypperLocksPath is where zypper records `zypper addlock`.
const zypperLocksPath = "/etc/zypp/locks"

// lockedNames is the set of package names a lock store holds. A nil or empty
// set means nothing is locked, which is the normal state of most hosts.
type lockedNames map[string]struct{}

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
// versionlock plugin is not installed, so nothing is locked.
func readVersionlock(fs afero.Fs) lockedNames {
	for _, p := range versionlockPaths {
		f, err := fs.Open(p)
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			log.Debug().Err(err).Str("path", p).Msg("could not read the versionlock store")
			continue
		}

		if strings.HasSuffix(p, ".toml") {
			return parseVersionlockTOML(raw)
		}
		return parseVersionlockList(string(raw))
	}
	return nil
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
		if entry == "" {
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
// installed package is held.
type versionlockTOML struct {
	Packages []struct {
		Name string `toml:"name"`
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
		if pkg.Name != "" {
			out[pkg.Name] = struct{}{}
		}
	}
	return out
}

// readZypperLocks returns the package names locked with `zypper addlock`. The
// store is a paragraph per lock:
//
//	type: package
//	match_type: glob
//	case_sensitive: on
//	solvable_name: vim
//
// A lock may target something other than a package (a pattern, a product), and
// those are skipped: they do not hold an installed package at its version.
func readZypperLocks(fs afero.Fs) lockedNames {
	f, err := fs.Open(zypperLocksPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	raw, err := io.ReadAll(f)
	if err != nil {
		log.Debug().Err(err).Msg("could not read the zypper lock store")
		return nil
	}
	return parseZypperLocks(string(raw))
}

func parseZypperLocks(content string) lockedNames {
	out := lockedNames{}

	// Paragraphs are separated by blank lines. A lock with no explicit type is
	// a package lock, which is what zypper writes by default.
	for _, block := range strings.Split(content, "\n\n") {
		name := ""
		isPackage := true
		for _, line := range strings.Split(block, "\n") {
			key, value, found := strings.Cut(line, ":")
			if !found {
				continue
			}
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			switch key {
			case "solvable_name":
				name = value
			case "type":
				isPackage = value == "package"
			}
		}
		if name != "" && isPackage {
			out[name] = struct{}{}
		}
	}
	return out
}

// markPinned flags the packages a lock store holds. Called once per listing,
// so the store is read once rather than once per package.
func markPinned(pkgs []Package, locks lockedNames) []Package {
	if len(locks) == 0 {
		return pkgs
	}
	for i := range pkgs {
		if locks.has(pkgs[i].Name) {
			pkgs[i].Pinned = true
		}
	}
	return pkgs
}
