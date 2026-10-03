// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/haproxy"
	"go.mondoo.com/mql/providers/os/resources/systemd"
)

// systemdUnitDirs lists where systemd looks for a service unit, highest
// precedence first. Drop-ins live in <dir>/<unit>.d/*.conf.
var systemdUnitDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// systemdDropInDirs returns the drop-in directories the target's systemd
// reads besides a unit's own <unit>.d: the dash-prefix directories and the
// type-level service.d, by the systemd release installed on its filesystem.
func systemdDropInDirs(runtime *plugin.Runtime, afs *afero.Afero) systemd.DropInDirs {
	return dropInDirsOnDisk(afs, typeLevelDropInBackport(runtime))
}

// systemdBinaries are where the systemd manager is installed.
var systemdBinaries = []string{"/usr/lib/systemd/systemd", "/lib/systemd/systemd"}

// dropInDirsOnDisk picks the drop-in directories by the systemd release on
// the filesystem. A systemd without libsystemd-shared predates release 231
// (RHEL 7 ships 219), which reads only a unit's own <unit>.d.
func dropInDirsOnDisk(afs *afero.Afero, typeLevelBackport bool) systemd.DropInDirs {
	version := systemd.InstalledVersion(afs)
	if version == 0 {
		for _, bin := range systemdBinaries {
			if ok, _ := afs.Exists(bin); ok {
				return systemd.DropInDirs{}
			}
		}
	}
	return systemd.DropInDirsForVersion(version, typeLevelBackport)
}

// systemdServiceArgv returns the command line (argv[0] included) that the
// first of the given service units that exists runs: its ExecStart= with
// the unit's drop-ins applied and its Environment= and EnvironmentFile=
// variables expanded. dirs selects the drop-in directories besides
// <unit>.d (see systemdDropInDirs). It returns nil when none of the units
// exists.
func systemdServiceArgv(afs *afero.Afero, dirs systemd.DropInDirs, units ...string) []string {
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
		contents := []string{unit}
		for _, p := range systemd.FindDropIns(afs, name, dirs) {
			if data, err := afs.ReadFile(p); err == nil {
				contents = append(contents, string(data))
			}
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
