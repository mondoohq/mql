// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"fmt"
	"io"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// SystemdTimer represents a systemd timer unit.
type SystemdTimer struct {
	Name        string
	Description string
	Installed   bool
	Enabled     bool
	Masked      bool
	Static      bool
	Running     bool
}

// SystemdTimerManager queries systemd for timer units via systemctl commands.
type SystemdTimerManager struct {
	conn shared.Connection
}

func NewSystemdTimerManager(conn shared.Connection) *SystemdTimerManager {
	return &SystemdTimerManager{conn: conn}
}

// fsFallback reads the timer unit files off disk. `systemctl list-units` and
// `systemctl show` need a running systemd to answer, so they are not available
// in a container, a chroot, a rescue boot, or on a host that keeps unit files
// around while another init runs. They report that by exiting non-zero with
// nothing on stdout, which parses into "no properties" rather than a failure,
// and every timer then reads back with a blank description and no schedule.
func (m *SystemdTimerManager) fsFallback() *SystemdFSTimerManager {
	return &SystemdFSTimerManager{Fs: m.conn.FileSystem()}
}

func (m *SystemdTimerManager) List() ([]*SystemdTimer, error) {
	timers, err := m.listViaSystemctl()
	if err == nil {
		return timers, nil
	}

	log.Debug().Err(err).
		Msg("mql[systemd]> could not list timers through systemctl, reading unit files instead")
	return m.fsFallback().List()
}

func (m *SystemdTimerManager) listViaSystemctl() ([]*SystemdTimer, error) {
	// Step 1: Get all timer unit files (provides Enabled/Masked/Static/Installed)
	cmdList, err := m.conn.RunCommand("systemctl list-unit-files --type timer --all")
	if err != nil {
		return nil, err
	}
	if cmdList.ExitStatus != 0 {
		return nil, systemctlError("systemctl list-unit-files --type timer", cmdList)
	}

	timers, err := ParseSystemdTimerUnitFiles(cmdList.Stdout)
	if err != nil {
		return nil, err
	}

	// Step 2: Get running state from list-units (provides Running/Description)
	cmdUnits, err := m.conn.RunCommand("systemctl list-units --type timer --all")
	if err != nil {
		return nil, err
	}
	if cmdUnits.ExitStatus != 0 {
		return nil, systemctlError("systemctl list-units --type timer", cmdUnits)
	}

	unitStates, err := ParseSystemdTimerListUnits(cmdUnits.Stdout)
	if err != nil {
		return nil, err
	}

	// Step 3: Merge
	for _, timer := range timers {
		unitState, ok := unitStates[timer.Name]
		if !ok {
			continue
		}
		timer.Description = unitState.Description
		timer.Running = unitState.Running
		if !unitState.Installed {
			timer.Installed = false
		}
	}

	// Step 4: Add the units only list-units names, such as the instances of a
	// template. A failed show keeps what list-units told about them.
	listed := make(map[string]bool, len(timers))
	for _, timer := range timers {
		listed[ensureSystemdTimerUnit(timer.Name)] = true
	}
	loaded := make(map[string]bool, len(unitStates))
	for name, unitState := range unitStates {
		loaded[ensureSystemdTimerUnit(name)] = unitState.Installed
	}
	unlisted := systemdUnitsNotListed(loaded, listed)
	shown := showSystemdUnitStates(m.conn, unlisted)
	for _, unit := range unlisted {
		timer := unitStates[normalizeSystemdTimerName(unit)]
		if record, ok := shown[unit]; ok {
			timer.Description = record["Description"]
			timer.Running = record["ActiveState"] == "active"
			applyUnitFileState(&timer.Enabled, &timer.Masked, &timer.Static, record["UnitFileState"])
		}
		timers = append(timers, timer)
	}

	return timers, nil
}

func (m *SystemdTimerManager) Get(name string) (*SystemdTimer, error) {
	unit := ensureSystemdTimerUnit(name)
	cmd, err := m.conn.RunCommand(buildSystemdShowCommand([]string{unit}))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		// same reason as List: a systemctl that cannot answer must not read as
		// "there is no such timer"
		log.Debug().Err(systemctlError("systemctl show", cmd)).Str("unit", unit).
			Msg("mql[systemd]> could not read timer through systemctl, reading the unit file instead")
		return m.fsFallback().Get(name)
	}

	props, err := parseShowProperties(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	id := props["Id"]
	if id == "" || props["LoadState"] == "not-found" || props["LoadState"] == "" {
		return nil, fmt.Errorf("%w: %s", ErrServiceNotFound, name)
	}

	timer := &SystemdTimer{
		Name:        normalizeSystemdTimerName(id),
		Description: props["Description"],
		Installed:   true,
		Running:     props["ActiveState"] == "active",
	}
	applyUnitFileState(&timer.Enabled, &timer.Masked, &timer.Static, props["UnitFileState"])

	return timer, nil
}

// ShowTimerProperties runs systemctl show for timer-specific properties. It
// returns Unit, Persistent and OnCalendar; OnCalendar is absent for a timer
// with no calendar trigger.
func (m *SystemdTimerManager) ShowTimerProperties(name string) (map[string]string, error) {
	unit := ensureSystemdTimerUnit(name)
	cmd, err := m.conn.RunCommand(buildShowPropertyCommand("Unit,TimersCalendar,Persistent", unit))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		log.Debug().Err(systemctlError("systemctl show", cmd)).Str("unit", unit).
			Msg("mql[systemd]> could not read timer properties through systemctl, reading the unit file instead")
		return m.fsFallback().ShowTimerProperties(name)
	}

	props, err := parseShowProperties(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	// systemd has no OnCalendar property; the calendar triggers are in
	// TimersCalendar. Before systemd 245 that property prints as
	// "[unprintable]", and then the unit files are the only source.
	calendar, ok := parseTimersCalendar(props["TimersCalendar"])
	delete(props, "TimersCalendar")
	if !ok {
		fsProps, err := m.fsFallback().ShowTimerProperties(name)
		if err != nil {
			// systemd knows the timer, so a unit file it does not find is one
			// generated at runtime or kept outside the search path
			log.Debug().Err(err).Str("unit", unit).
				Msg("mql[systemd]> could not read the timer's calendar from its unit file")
			return props, nil
		}
		calendar = fsProps["OnCalendar"]
	}
	if calendar != "" {
		props["OnCalendar"] = calendar
	}

	return props, nil
}

// parseTimersCalendar extracts the calendar expressions from systemctl's
// TimersCalendar property, one per line as parseShowProperties joins them:
//
//	{ OnCalendar=*-*-* 03:00:00 ; next_elapse=Sat 2026-10-03 03:00:00 UTC }
//
// Several expressions are joined with a newline. An empty value means the
// timer has no calendar trigger. ok is false when the value cannot be read,
// which is what systemd before 245 prints ("[unprintable]").
func parseTimersCalendar(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}

	var exprs []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		inner, found := strings.CutPrefix(line, "{ OnCalendar=")
		if !found {
			return "", false
		}
		expr, _, found := strings.Cut(inner, " ; next_elapse=")
		if !found {
			return "", false
		}
		exprs = append(exprs, expr)
	}
	return strings.Join(exprs, "\n"), true
}

func ParseSystemdTimerUnitFiles(input io.Reader) ([]*SystemdTimer, error) {
	content, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("error executing systemctl list-unit-files --type timer: %v", err)
	}

	var timers []*SystemdTimer
	lines := strings.Split(string(content), "\n")
	if len(lines) < 2 {
		return timers, nil
	}

	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.Contains(line, "unit files listed.") {
			continue
		}

		timer := &SystemdTimer{
			Name:      normalizeSystemdTimerName(fields[0]),
			Installed: true,
		}
		applyUnitFileState(&timer.Enabled, &timer.Masked, &timer.Static, fields[1])
		timers = append(timers, timer)
	}

	return timers, nil
}

func ParseSystemdTimerListUnits(input io.Reader) (map[string]*SystemdTimer, error) {
	content, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("error reading systemctl list-units output: %v", err)
	}

	timers := map[string]*SystemdTimer{}
	jobCol := systemdListUnitsJobColumn(string(content))
	matches := SYSTEMD_LIST_UNITS_REGEX.FindAllStringSubmatch(string(content), -1)
	for _, match := range matches {
		unitName := match[1]
		if !strings.HasSuffix(unitName, ".timer") {
			continue
		}

		name := normalizeSystemdTimerName(unitName)
		timers[name] = &SystemdTimer{
			Name:        name,
			Description: systemdListUnitsDescription(match, jobCol),
			Running:     match[3] == "active",
			Installed:   match[2] != "not-found",
		}
	}

	return timers, nil
}

func normalizeSystemdTimerName(unit string) string {
	return strings.TrimSuffix(unit, ".timer")
}

func ensureSystemdTimerUnit(name string) string {
	if strings.HasSuffix(name, ".timer") {
		return name
	}
	return name + ".timer"
}
