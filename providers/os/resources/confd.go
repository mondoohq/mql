// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// Loading *.d configuration directories.
//
// libkmod (modprobe.d), systemd-sysctl and procps (sysctl.d) read their
// configuration the same way: a list of directories, highest priority first;
// only `*.conf` files that are not hidden; a file hides a same-named file in
// a lower-priority directory; and the surviving files are applied in file
// name order across all directories. The callers differ only in which
// directories they pass.

// isConfDFileName reports whether a directory entry with this name is read
// from a *.d configuration directory: hidden files are skipped and only
// `*.conf` files count. libkmod (modprobe.d) and systemd and procps (sysctl.d)
// apply the same rule.
func isConfDFileName(name string) bool {
	return !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".conf")
}

// selectConfDFiles applies the file selection libkmod, systemd and procps
// share to the entries found in each search directory. listings[i] holds the
// names of the non-directory entries of dirs[i]. The first directory that
// holds a given name wins, and the winners are returned as full paths ordered
// by file name (strcmp order), which is the order the files are applied in.
func selectConfDFiles(dirs []string, listings [][]string) []string {
	winners := map[string]string{}
	for i, dir := range dirs {
		if i >= len(listings) {
			break
		}
		for _, name := range listings[i] {
			if !isConfDFileName(name) {
				continue
			}
			if _, ok := winners[name]; ok {
				continue
			}
			winners[name] = path.Join(dir, name)
		}
	}

	names := make([]string, 0, len(winners))
	for name := range winners {
		names = append(names, name)
	}
	sort.Strings(names)

	res := make([]string, len(names))
	for i, name := range names {
		res[i] = winners[name]
	}
	return res
}

// listConfDFiles returns the configuration files read from the *.d search
// directories dirs, highest priority first, in the order they are applied.
// Each directory is listed one level deep (subdirectories are ignored),
// symlinked files are followed, and missing directories are skipped. A
// directory that exists but can't be checked or listed doesn't stop the walk:
// the files from the other directories are still returned, together with the
// joined errors.
func listConfDFiles(runtime *plugin.Runtime, dirs []string) ([]string, error) {
	conn := runtime.Connection.(shared.Connection)
	fs := conn.FileSystem()

	var errs []error
	listings := make([][]string, len(dirs))
	for i, dir := range dirs {
		raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(dir),
		})
		if err != nil {
			return nil, err
		}
		exists := raw.(*mqlFile).GetExists()
		if exists.Error != nil {
			errs = append(errs, exists.Error)
			continue
		}
		if !exists.Data {
			continue
		}

		entries, err := afero.ReadDir(fs, dir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if entry.Mode()&os.ModeSymlink != 0 {
				// libkmod and systemd stat through the link: a link to a
				// directory is skipped and a dangling link has nothing to read.
				target, err := fs.Stat(path.Join(dir, entry.Name()))
				if err != nil || target.IsDir() {
					continue
				}
			}
			listings[i] = append(listings[i], entry.Name())
		}
	}

	return selectConfDFiles(dirs, listings), errors.Join(errs...)
}
