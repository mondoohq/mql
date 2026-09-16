// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"os"
	"path"
	"sort"
	"strings"

	"github.com/coreos/go-systemd/unit"
	"github.com/spf13/afero"
)

// The `systemctl show` properties recoverable from a unit file on disk are
// Description, Wants, Requires, After, Before, FragmentPath, UnitFileState and
// LoadState. The runtime state of a target (ActiveState, SubState) is not: it
// exists only in a running systemd.

// ListSystemdFSTargetNames returns every .target unit file on disk, without the
// .target suffix, de-duplicated by search-path precedence.
//
// `systemctl list-unit-files` reads the same files, so this is what is left
// when systemctl itself cannot run -- in a container, a chroot, a rescue boot,
// or on a host that keeps unit files around while another init runs.
func ListSystemdFSTargetNames(fs afero.Fs) []string {
	seen := map[string]bool{}
	names := []string{}

	for _, searchPath := range systemdUnitSearchPath {
		entries, err := afero.ReadDir(fs, searchPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".target") {
				continue
			}
			name := strings.TrimSuffix(entry.Name(), ".target")
			if seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
	}

	sort.Strings(names)
	return names
}

// ReadSystemdFSTargetProperties reads the named targets' unit files and returns
// what `systemctl show` would have reported for the properties a unit file
// carries. A target whose file cannot be read is left out of the map rather
// than reported as a target carrying nothing.
func ReadSystemdFSTargetProperties(fs afero.Fs, names []string) map[string]map[string]string {
	enabledSet := buildEnabledSet(fs)
	out := make(map[string]map[string]string, len(names))

	for _, name := range names {
		unitFile := name + ".target"
		for _, searchPath := range systemdUnitSearchPath {
			unitPath := path.Join(searchPath, unitFile)
			if _, err := fs.Stat(unitPath); err != nil {
				continue
			}

			props, err := readSystemdTargetUnit(fs, unitPath)
			if err != nil {
				break
			}
			if enabledSet[unitFile] {
				props["UnitFileState"] = "enabled"
			}
			out[name] = props
			break
		}
	}

	return out
}

func readSystemdTargetUnit(fs afero.Fs, unitPath string) (map[string]string, error) {
	props := map[string]string{
		"FragmentPath": unitPath,
		"LoadState":    "loaded",
	}

	// a masked unit is a symlink to /dev/null, which carries no settings
	if lr, ok := fs.(afero.LinkReader); ok {
		linkPath, err := lr.ReadlinkIfPossible(unitPath)
		if err == nil && linkPath == os.DevNull {
			props["LoadState"] = "masked"
			props["UnitFileState"] = "masked"
			return props, nil
		}
	}

	f, err := fs.Open(unitPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	opts, err := unit.Deserialize(f)
	if err != nil {
		return nil, err
	}

	hasInstall := false
	for _, o := range opts {
		if o.Section == "Install" {
			hasInstall = true
		}
		if o.Section != "Unit" {
			continue
		}
		switch o.Name {
		case "Description", "Wants", "Requires", "After", "Before":
			// a unit file may repeat a list setting, and systemd accumulates
			// rather than replaces; systemctl show reports the accumulation
			// space separated
			if existing, ok := props[o.Name]; ok && o.Name != "Description" {
				props[o.Name] = existing + " " + o.Value
			} else {
				props[o.Name] = o.Value
			}
		}
	}

	// systemctl calls a unit with no [Install] section "static" -- there is no
	// way to enable it -- and one that has an [Install] section but is not
	// symlinked into a .wants/.requires directory "disabled". Leaving the
	// latter blank would read as "not measured" for a target that is measurably
	// off.
	if _, ok := props["UnitFileState"]; !ok {
		if hasInstall {
			props["UnitFileState"] = "disabled"
		} else {
			props["UnitFileState"] = "static"
		}
	}

	return props, nil
}
