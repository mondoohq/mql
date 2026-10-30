// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path"
	"strings"

	"github.com/spf13/afero"
)

// vendorConfigRoot is the vendor configuration tree that ships distribution
// defaults outside of /etc. openSUSE Leap 16 and SUSE Linux Enterprise 16 moved
// their packaged defaults there: /etc holds only what an administrator changed,
// while the shipped file lives at the same relative path under /usr/etc. A host
// that never customized sshd_config therefore has no /etc/ssh/sshd_config at
// all, only /usr/etc/ssh/sshd_config.
//
// The precedence is the one systemd documents for its split configuration
// trees: /etc wins when it has the file, /usr/etc supplies it otherwise.
const vendorConfigRoot = "/usr/etc"

// vendorConfigCandidates expands an /etc path into the locations it may be
// readable at, most specific first. Paths outside /etc are returned unchanged,
// so callers can pass any configured path without special-casing.
func vendorConfigCandidates(p string) []string {
	if p != "/etc" && !strings.HasPrefix(p, "/etc/") {
		return []string{p}
	}
	return []string{p, vendorConfigRoot + strings.TrimPrefix(p, "/etc")}
}

// resolveVendorConfigPath returns the first candidate for p that exists on fs.
// When none exists it returns p unchanged, so a "file not found" error still
// names the canonical location rather than the fallback.
func resolveVendorConfigPath(fs afero.Fs, p string) string {
	if fs == nil {
		return p
	}
	for _, candidate := range vendorConfigCandidates(p) {
		if _, err := fs.Stat(candidate); err == nil {
			return candidate
		}
	}
	return p
}

// vendorConfigDirs returns every candidate for dir that exists on fs and is a
// directory, /etc first. Drop-in directories merge across the two trees rather
// than shadowing each other wholesale, which is why this returns a list where
// resolveVendorConfigPath returns one path.
func vendorConfigDirs(fs afero.Fs, dir string) []string {
	if fs == nil {
		return nil
	}
	var dirs []string
	for _, candidate := range vendorConfigCandidates(dir) {
		fi, err := fs.Stat(candidate)
		if err != nil || !fi.IsDir() {
			continue
		}
		dirs = append(dirs, candidate)
	}
	return dirs
}

// vendorConfigShadowed reports whether a drop-in read from a /usr/etc directory
// is overridden by a file of the same name in the matching /etc directory. Only
// the file name matters: sshd, sudo and logrotate all resolve a drop-in by its
// basename, so /etc/ssh/sshd_config.d/50-foo.conf replaces the /usr/etc copy
// instead of being read in addition to it.
func vendorConfigShadowed(fs afero.Fs, filePath string) bool {
	if fs == nil || !strings.HasPrefix(filePath, vendorConfigRoot+"/") {
		return false
	}
	etcPath := "/etc" + strings.TrimPrefix(filePath, vendorConfigRoot)
	if path.Clean(etcPath) != etcPath {
		return false
	}
	_, err := fs.Stat(etcPath)
	return err == nil
}
