// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/coreos/go-systemd/unit"
	"github.com/spf13/afero"
)

// SystemdFSTimerManager reads timer unit files directly from the filesystem.
// It is used when command execution is not available (e.g., filesystem scans).
// Running state is not available from the filesystem and defaults to false.
type SystemdFSTimerManager struct {
	Fs afero.Fs
}

func (m *SystemdFSTimerManager) List() ([]*SystemdTimer, error) {
	enabledSet := buildEnabledSet(m.Fs)
	seen := map[string]bool{}
	var timers []*SystemdTimer

	for _, searchPath := range systemdUnitSearchPath {
		entries, err := afero.ReadDir(m.Fs, searchPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}

		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".timer") {
				continue
			}
			name := normalizeSystemdTimerName(entry.Name())
			if seen[name] {
				continue
			}
			seen[name] = true

			unitPath := path.Join(searchPath, entry.Name())
			timer, err := m.readTimerUnit(name, unitPath)
			if err != nil {
				continue
			}
			timer.Enabled = enabledSet[entry.Name()]
			timers = append(timers, timer)
		}
	}

	return timers, nil
}

func (m *SystemdFSTimerManager) Get(name string) (*SystemdTimer, error) {
	timers, err := m.List()
	if err != nil {
		return nil, err
	}
	for _, t := range timers {
		if t.Name == name {
			return t, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrServiceNotFound, name)
}

func (m *SystemdFSTimerManager) ShowTimerProperties(name string) (map[string]string, error) {
	unitName := ensureSystemdTimerUnit(name)
	for _, searchPath := range systemdUnitSearchPath {
		unitPath := path.Join(searchPath, unitName)
		if _, err := m.Fs.Stat(unitPath); err != nil {
			continue
		}
		return m.readTimerProperties(unitName, unitPath)
	}
	return nil, fmt.Errorf("%w: %s", ErrServiceNotFound, name)
}

func (m *SystemdFSTimerManager) readTimerUnit(name, unitPath string) (*SystemdTimer, error) {
	timer := &SystemdTimer{
		Name:      name,
		Installed: true,
	}

	// Check if masked (symlink to /dev/null)
	if lr, ok := m.Fs.(afero.LinkReader); ok {
		linkPath, err := lr.ReadlinkIfPossible(unitPath)
		if err == nil && linkPath == "/dev/null" {
			timer.Masked = true
			return timer, nil
		}
	}

	f, err := m.Fs.Open(unitPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	opts, err := unit.Deserialize(f)
	if err != nil {
		return nil, err
	}

	var hasInstall bool
	for _, o := range opts {
		switch {
		case o.Section == "Unit" && o.Name == "Description":
			timer.Description = o.Value
		case o.Section == "Install":
			hasInstall = true
		}
	}
	timer.Static = !timer.Masked && !hasInstall

	return timer, nil
}

// readTimerProperties reads the timer settings from the unit file and its
// drop-ins, in the order systemd applies them. OnCalendar is a list: every
// assignment adds an expression and an empty one clears those before it.
// Several expressions are joined with a newline.
func (m *SystemdFSTimerManager) readTimerProperties(unitName, unitPath string) (map[string]string, error) {
	props := map[string]string{}
	var calendar []string

	files := append([]string{unitPath}, (&SystemdFSUnitManager{Fs: m.Fs}).dropInFiles(unitName)...)
	for i, file := range files {
		f, err := m.Fs.Open(file)
		if err != nil {
			if i == 0 {
				return nil, err
			}
			// a drop-in that cannot be read does not erase the unit file
			continue
		}
		opts, err := unit.Deserialize(f)
		f.Close()
		if err != nil {
			if i == 0 {
				return nil, err
			}
			continue
		}

		for _, o := range opts {
			if o.Section != "Timer" {
				continue
			}
			switch o.Name {
			case "OnCalendar":
				if o.Value == "" {
					calendar = nil
					continue
				}
				calendar = append(calendar, o.Value)
			case "Persistent", "Unit":
				props[o.Name] = o.Value
			}
		}
	}
	if len(calendar) > 0 {
		props["OnCalendar"] = strings.Join(calendar, "\n")
	}

	// If Unit is not explicitly set, systemd defaults to <name>.service
	if props["Unit"] == "" {
		base := path.Base(unitPath)
		props["Unit"] = normalizeSystemdTimerName(base) + ".service"
	}

	return props, nil
}
