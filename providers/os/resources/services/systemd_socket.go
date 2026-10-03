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

// SystemdSocket represents a systemd socket unit.
type SystemdSocket struct {
	Name        string
	Description string
	Installed   bool
	Enabled     bool
	Masked      bool
	Static      bool
	Running     bool
}

// SystemdSocketManager queries systemd for socket units via systemctl commands.
type SystemdSocketManager struct {
	conn shared.Connection
}

func NewSystemdSocketManager(conn shared.Connection) *SystemdSocketManager {
	return &SystemdSocketManager{conn: conn}
}

// fsFallback reads the socket unit files off disk, for the same reason
// SystemdTimerManager.fsFallback does.
func (m *SystemdSocketManager) fsFallback() *SystemdFSSocketManager {
	return &SystemdFSSocketManager{Fs: m.conn.FileSystem()}
}

func (m *SystemdSocketManager) List() ([]*SystemdSocket, error) {
	sockets, err := m.listViaSystemctl()
	if err == nil {
		return sockets, nil
	}

	log.Debug().Err(err).
		Msg("mql[systemd]> could not list sockets through systemctl, reading unit files instead")
	return m.fsFallback().List()
}

func (m *SystemdSocketManager) listViaSystemctl() ([]*SystemdSocket, error) {
	// Step 1: Get all socket unit files (provides Enabled/Masked/Static/Installed)
	cmdList, err := m.conn.RunCommand("systemctl list-unit-files --type socket --all")
	if err != nil {
		return nil, err
	}
	if cmdList.ExitStatus != 0 {
		return nil, systemctlError("systemctl list-unit-files --type socket", cmdList)
	}

	sockets, err := ParseSystemdSocketUnitFiles(cmdList.Stdout)
	if err != nil {
		return nil, err
	}

	// Step 2: Get running state from list-units (provides Running/Description)
	cmdUnits, err := m.conn.RunCommand("systemctl list-units --type socket --all")
	if err != nil {
		return nil, err
	}
	if cmdUnits.ExitStatus != 0 {
		return nil, systemctlError("systemctl list-units --type socket", cmdUnits)
	}

	unitStates, err := ParseSystemdSocketListUnits(cmdUnits.Stdout)
	if err != nil {
		return nil, err
	}

	// Step 3: Merge
	for _, socket := range sockets {
		unitState, ok := unitStates[socket.Name]
		if !ok {
			continue
		}
		socket.Description = unitState.Description
		socket.Running = unitState.Running
		if !unitState.Installed {
			socket.Installed = false
		}
	}

	// Step 4: Add the units only list-units names, such as the instances of a
	// template. A failed show keeps what list-units told about them.
	listed := make(map[string]bool, len(sockets))
	for _, socket := range sockets {
		listed[ensureSystemdSocketUnit(socket.Name)] = true
	}
	loaded := make(map[string]bool, len(unitStates))
	for name, unitState := range unitStates {
		loaded[ensureSystemdSocketUnit(name)] = unitState.Installed
	}
	unlisted := systemdUnitsNotListed(loaded, listed)
	shown := showSystemdUnitStates(m.conn, unlisted)
	for _, unit := range unlisted {
		socket := unitStates[normalizeSystemdSocketName(unit)]
		if record, ok := shown[unit]; ok {
			socket.Description = record["Description"]
			socket.Running = record["ActiveState"] == "active"
			applyUnitFileState(&socket.Enabled, &socket.Masked, &socket.Static, record["UnitFileState"])
		}
		sockets = append(sockets, socket)
	}

	return sockets, nil
}

func (m *SystemdSocketManager) Get(name string) (*SystemdSocket, error) {
	unit := ensureSystemdSocketUnit(name)
	cmd, err := m.conn.RunCommand(buildSystemdShowCommand([]string{unit}))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		// same reason as List: a systemctl that cannot answer must not read as
		// "there is no such socket"
		log.Debug().Err(systemctlError("systemctl show", cmd)).Str("unit", unit).
			Msg("mql[systemd]> could not read socket through systemctl, reading the unit file instead")
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

	socket := &SystemdSocket{
		Name:        normalizeSystemdSocketName(id),
		Description: props["Description"],
		Installed:   true,
		Running:     props["ActiveState"] == "active",
	}
	applyUnitFileState(&socket.Enabled, &socket.Masked, &socket.Static, props["UnitFileState"])

	return socket, nil
}

// ShowSocketProperties runs systemctl show for socket-specific properties
// including Listen for addresses, Triggers for the activated unit, and Accept.
func (m *SystemdSocketManager) ShowSocketProperties(name string) (map[string]string, error) {
	unit := ensureSystemdSocketUnit(name)
	cmd, err := m.conn.RunCommand(buildShowPropertyCommand("Triggers,Accept,Listen", unit))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		log.Debug().Err(systemctlError("systemctl show", cmd)).Str("unit", unit).
			Msg("mql[systemd]> could not read socket properties through systemctl, reading the unit file instead")
		return m.fsFallback().ShowSocketProperties(name)
	}

	props, err := parseShowProperties(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	foldListenTypeProperties(props)
	return props, nil
}

// systemdListenTypes are the per-type listen settings, in the order they are
// reported, with the type name systemd prints in a Listen= value.
var systemdListenTypes = []struct{ key, kind string }{
	{"ListenStream", "Stream"},
	{"ListenDatagram", "Datagram"},
	{"ListenSequentialPacket", "SequentialPacket"},
	{"ListenFIFO", "FIFO"},
	{"ListenSpecial", "Special"},
	{"ListenNetlink", "Netlink"},
	{"ListenMessageQueue", "MessageQueue"},
	{"ListenUSBFunction", "USBFunction"},
}

// foldListenTypeProperties builds Listen from the per-type settings when
// systemctl printed those instead. Asked for --property=Listen, systemd 219
// (RHEL 7), 232 (Debian 9) and 237 (Ubuntu 18.04) answer with
// ListenStream=127.0.0.1:7777 and the like, so every socket read as listening
// nowhere.
func foldListenTypeProperties(props map[string]string) {
	if props["Listen"] != "" {
		return
	}
	lines := []string{}
	for _, t := range systemdListenTypes {
		for _, addr := range strings.Split(props[t.key], "\n") {
			if addr = strings.TrimSpace(addr); addr != "" {
				lines = append(lines, addr+" ("+t.kind+")")
			}
		}
	}
	if len(lines) > 0 {
		props["Listen"] = strings.Join(lines, "\n")
	}
}

func ParseSystemdSocketUnitFiles(input io.Reader) ([]*SystemdSocket, error) {
	content, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("error executing systemctl list-unit-files --type socket: %v", err)
	}

	var sockets []*SystemdSocket
	lines := strings.Split(string(content), "\n")
	if len(lines) < 2 {
		return sockets, nil
	}

	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.Contains(line, "unit files listed.") {
			continue
		}

		socket := &SystemdSocket{
			Name:      normalizeSystemdSocketName(fields[0]),
			Installed: true,
		}
		applyUnitFileState(&socket.Enabled, &socket.Masked, &socket.Static, fields[1])
		sockets = append(sockets, socket)
	}

	return sockets, nil
}

func ParseSystemdSocketListUnits(input io.Reader) (map[string]*SystemdSocket, error) {
	content, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("error reading systemctl list-units output: %v", err)
	}

	sockets := map[string]*SystemdSocket{}
	jobCol := systemdListUnitsJobColumn(string(content))
	matches := SYSTEMD_LIST_UNITS_REGEX.FindAllStringSubmatch(string(content), -1)
	for _, match := range matches {
		unitName := match[1]
		if !strings.HasSuffix(unitName, ".socket") {
			continue
		}

		name := normalizeSystemdSocketName(unitName)
		sockets[name] = &SystemdSocket{
			Name:        name,
			Description: systemdListUnitsDescription(match, jobCol),
			Running:     match[3] == "active",
			Installed:   match[2] != "not-found",
		}
	}

	return sockets, nil
}

func normalizeSystemdSocketName(unit string) string {
	return strings.TrimSuffix(unit, ".socket")
}

func ensureSystemdSocketUnit(name string) string {
	if strings.HasSuffix(name, ".socket") {
		return name
	}
	return name + ".socket"
}

// ParseListenProperty parses the Listen= value from systemctl show output.
// Multi-listen sockets produce multiple Listen= lines which are joined with "\n"
// by parseShowProperties. Each line is one of:
//   - "/run/dbus/system_bus_socket (Stream)" — simple format
//   - "{ path=/run/...; type=Stream }" — structured format
func ParseListenProperty(listen string) []string {
	if listen == "" {
		return nil
	}

	var addresses []string
	for _, line := range strings.Split(listen, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Structured format: "{ path=<path> ; type=<type> }"
		if strings.HasPrefix(line, "{") {
			inner := strings.Trim(line, "{ }")
			for _, part := range strings.Split(inner, ";") {
				part = strings.TrimSpace(part)
				if after, ok := strings.CutPrefix(part, "path="); ok {
					addresses = append(addresses, after)
				}
			}
			continue
		}

		// Simple format: "<address> (<type>)"
		if idx := strings.LastIndex(line, " ("); idx > 0 {
			addresses = append(addresses, strings.TrimSpace(line[:idx]))
		} else {
			addresses = append(addresses, line)
		}
	}

	if len(addresses) == 0 {
		return nil
	}
	return addresses
}
