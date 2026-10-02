// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/resources/haproxy"
)

// systemdUnitDirs lists where systemd looks for a service unit, highest
// precedence first. Drop-ins live in <dir>/<unit>.d/*.conf.
var systemdUnitDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// systemdServiceArgv returns the command line (argv[0] included) that the
// first of the given service units that exists runs: its ExecStart= with
// the unit's drop-ins applied and its Environment= and EnvironmentFile=
// variables expanded. It returns nil when none of the units exists.
func systemdServiceArgv(afs *afero.Afero, units ...string) []string {
	for _, name := range units {
		var unit string
		for _, dir := range systemdUnitDirs {
			data, err := afs.ReadFile(filepath.Join(dir, name))
			if err == nil {
				unit = string(data)
				break
			}
		}
		if unit == "" {
			continue
		}

		// Drop-ins with the same name shadow each other by directory
		// precedence and apply in file name order.
		dropIns := map[string]string{}
		for i := len(systemdUnitDirs) - 1; i >= 0; i-- {
			dir := filepath.Join(systemdUnitDirs[i], name+".d")
			entries, err := afs.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
					continue
				}
				if data, err := afs.ReadFile(filepath.Join(dir, e.Name())); err == nil {
					dropIns[e.Name()] = string(data)
				}
			}
		}
		names := make([]string, 0, len(dropIns))
		for n := range dropIns {
			names = append(names, n)
		}
		sort.Strings(names)
		contents := []string{unit}
		for _, n := range names {
			contents = append(contents, dropIns[n])
		}

		svc := haproxy.ParseSystemdService(contents...)
		var envFiles []string
		for _, p := range svc.EnvironmentFiles {
			if data, err := afs.ReadFile(p); err == nil {
				envFiles = append(envFiles, string(data))
			}
		}
		return haproxy.ServiceArgv(svc, envFiles)
	}
	return nil
}
