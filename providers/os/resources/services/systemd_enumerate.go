// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"io"
	"path"
	"sort"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// systemdListsSysVUnitFilesSince is the first systemd release whose
// list-unit-files names the units systemd-sysv-generator writes for SysV init
// scripts. systemd 219 (RHEL 7) leaves them out, and a SysV service that is
// neither running nor enabled is not loaded either, so neither listing names it.
const systemdListsSysVUnitFilesSince = 220

// sysvInitScriptDirs are where SysV init scripts live. On RHEL 7 /etc/init.d is
// a symlink to /etc/rc.d/init.d.
var sysvInitScriptDirs = []string{"/etc/rc.d/init.d", "/etc/init.d"}

// sysvInitScriptUnits names the service unit systemd-sysv-generator makes for
// each executable script in the init script directory. Helpers the scripts
// source (RHEL's 0644 `functions`) and READMEs are not executable and are left
// out; a name that is still not a service loads as not-found and the caller
// drops it.
func sysvInitScriptUnits(fs afero.Fs) []string {
	for _, dir := range sysvInitScriptDirs {
		entries, err := afero.ReadDir(fs, dir)
		if err != nil {
			continue
		}
		units := []string{}
		for _, entry := range entries {
			if entry.IsDir() || entry.Mode().Perm()&0o111 == 0 {
				continue
			}
			name := path.Base(entry.Name())
			if strings.HasPrefix(name, ".") {
				continue
			}
			units = append(units, name+".service")
		}
		sort.Strings(units)
		return units
	}
	return nil
}

// parseSystemdLoadedUnitNames reads the service names out of
// `systemctl list-units --type service --all --plain --no-legend`, leaving out
// units that load as not-found (named by another unit's After= or Conflicts=,
// or a SysV service whose script was removed) and uninstantiated templates.
func parseSystemdLoadedUnitNames(input io.Reader) ([]string, error) {
	content, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		// a failed unit is marked with a leading bullet on releases that
		// ignore --plain for it
		if len(fields) > 0 && fields[0] == "●" {
			fields = fields[1:]
		}
		if len(fields) < 2 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		if fields[1] == "not-found" || isSystemdTemplateUnit(fields[0]) {
			continue
		}
		names = append(names, fields[0])
	}
	return names, nil
}

// isSystemdInstanceName reports whether a service name, with or without its
// .service suffix, is an instance of a template (getty@tty1).
func isSystemdInstanceName(name string) bool {
	name = strings.TrimSuffix(name, ".service")
	at := strings.IndexByte(name, '@')
	return at > 0 && at < len(name)-1
}

// systemdAnswering reports whether systemctl reaches a running systemd, by
// asking for the manager's own Version property. A batch "systemctl show"
// that fails while this succeeds failed because of a unit in the batch, not
// because systemd is not there.
func systemdAnswering(conn shared.Connection) bool {
	cmd, err := conn.RunCommand("systemctl show --property=Version")
	if err != nil || cmd.ExitStatus != 0 {
		return false
	}
	out, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(string(out)), "Version=")
}

// bisectSystemdShow runs show over units and, when the batch fails while
// systemd is answering, splits it and asks each half, down to single units.
//
// systemd 219 (RHEL 7) answers a whole batch with "Failed to get properties:
// Access denied", exit 1 and no output, when a single SysV service in it is
// running while its init script was deleted. Without the split, every other
// unit in the batch lost its state. A unit that fails on its own is reported
// through skip and left out.
func bisectSystemdShow[T any](units []string, show func([]string) (T, error), merge func(T), skip func(string, error), answering func() bool) error {
	res, err := show(units)
	if err == nil {
		merge(res)
		return nil
	}
	if len(units) == 1 {
		if answering() {
			skip(units[0], err)
			return nil
		}
		return err
	}
	if !answering() {
		return err
	}
	mid := len(units) / 2
	if err := bisectSystemdShow(units[:mid], show, merge, skip, answering); err != nil {
		return err
	}
	return bisectSystemdShow(units[mid:], show, merge, skip, answering)
}

// systemdLegacyPathProperties maps the directive names systemd before 231
// used onto the ones that replaced them. systemd 219 (RHEL 7) prints
// ReadOnlyDirectories and never ReadOnlyPaths; later releases accept the old
// names in a unit file as aliases.
var systemdLegacyPathProperties = map[string]string{
	"ReadWriteDirectories":    "ReadWritePaths",
	"ReadOnlyDirectories":     "ReadOnlyPaths",
	"InaccessibleDirectories": "InaccessiblePaths",
}

// foldSystemdLegacyPathProperties copies a pre-231 directory setting onto the
// property that replaced it, when the record does not carry the new one.
func foldSystemdLegacyPathProperties(record map[string]string) {
	for legacy, current := range systemdLegacyPathProperties {
		value, ok := record[legacy]
		if !ok {
			continue
		}
		if _, has := record[current]; !has {
			record[current] = value
		}
	}
}
