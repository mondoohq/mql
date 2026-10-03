// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"

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
// (RHEL 7 ships 219), which reads only a unit's own <unit>.d. When neither
// the library nor the manager binary is there, nothing tells the release, so
// every directory a current systemd reads is searched.
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
	name, aliases, unit, err := systemdServiceUnit(afs, units...)
	if err != nil || name == "" {
		return nil
	}

	// Drop-ins with the same name shadow each other by directory
	// precedence and apply in file name order.
	contents := []string{unit}
	for _, p := range systemd.FindDropIns(afs, name, dirs, aliases...) {
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

// systemdServiceUnit returns the first of the given service units that is
// installed: the name it was found under, its other names and the unit
// file's content. The other names are the given units and the unit's Alias=
// names that are installed as the same unit, which is what systemctl enable
// does by linking each alias to the unit file (SUSE's apache2.service is also
// httpd.service and apache.service once enabled). systemd applies the
// drop-ins of every name. A unit that is not installed gives an empty name;
// a unit file that cannot be read is an error.
func systemdServiceUnit(afs *afero.Afero, units ...string) (string, []string, string, error) {
	name, content, err := readSystemdUnit(afs, units...)
	if err != nil || name == "" {
		return "", nil, "", err
	}

	candidates := append(append([]string{}, units...), systemdUnitAliases(content)...)
	seen := map[string]bool{name: true}
	var aliases []string
	for _, c := range candidates {
		if seen[c] {
			continue
		}
		seen[c] = true
		// an alias reads as the unit it links to; a different file under that
		// name is another unit
		if _, other, err := readSystemdUnit(afs, c); err == nil && other == content {
			aliases = append(aliases, c)
		}
	}
	return name, aliases, content, nil
}

// readSystemdUnit returns the name and content of the first of the given
// units found in systemdUnitDirs, or an empty name when none is installed.
func readSystemdUnit(afs *afero.Afero, units ...string) (string, string, error) {
	for _, name := range units {
		for _, dir := range systemdUnitDirs {
			data, err := afs.ReadFile(filepath.Join(dir, name))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return "", "", err
			}
			return name, string(data), nil
		}
	}
	return "", "", nil
}

// systemdUnitAliases returns the Alias= names of a unit's [Install] section.
func systemdUnitAliases(content string) []string {
	var aliases []string
	install := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			install = line == "[Install]"
			continue
		}
		if v, ok := strings.CutPrefix(line, "Alias="); ok && install {
			aliases = append(aliases, strings.Fields(v)...)
		}
	}
	return aliases
}
