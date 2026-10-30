// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"fmt"
	"path"
	"strings"

	"github.com/coreos/go-systemd/unit"
	"github.com/spf13/afero"
)

// SystemdFSSocketManager reads socket unit files directly from the filesystem.
// It is used when command execution is not available (e.g., filesystem scans).
// Running state is not available from the filesystem and defaults to false.
type SystemdFSSocketManager struct {
	Fs afero.Fs
}

func (m *SystemdFSSocketManager) List() ([]*SystemdSocket, error) {
	units, err := readSystemdUnitFiles(m.Fs, ".socket")
	if err != nil {
		return nil, err
	}
	byName := make(map[string]*systemdUnitFile, len(units))
	for _, u := range units {
		byName[u.Name] = u
	}
	var sockets []*SystemdSocket
	for _, u := range units {
		if isSystemdInstanceUnit(u.Name) {
			continue
		}
		name := normalizeSystemdSocketName(u.Name)
		if u.State == "alias" {
			// an alias reads as the unit it names, under its own name
			target, ok := byName[u.Target]
			if !ok {
				continue
			}
			u = &systemdUnitFile{Name: u.Name, State: target.State, Path: target.Path, Description: target.Description}
		}
		socket := &SystemdSocket{Name: name, Installed: true, Description: u.Description}
		if u.State != "masked" {
			read, err := m.readSocketUnit(name, u.Path)
			if err != nil {
				continue
			}
			socket = read
			if socket.Description == "" && !isSystemdTemplateUnit(u.Name) {
				socket.Description = u.Description
			}
		}
		// the unit-file state as systemctl reports it: a unit without an
		// [Install] section is static even when something links it, and a
		// link a package ships under /usr/lib does not enable it
		applyUnitFileState(&socket.Enabled, &socket.Masked, &socket.Static, u.State)
		sockets = append(sockets, socket)
	}
	return sockets, nil
}

func (m *SystemdFSSocketManager) Get(name string) (*SystemdSocket, error) {
	sockets, err := m.List()
	if err != nil {
		return nil, err
	}
	for _, s := range sockets {
		if s.Name == name {
			return s, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrServiceNotFound, name)
}

func (m *SystemdFSSocketManager) ShowSocketProperties(name string) (map[string]string, error) {
	unitName := ensureSystemdSocketUnit(name)
	for _, searchPath := range systemdUnitSearchPath {
		unitPath := path.Join(searchPath, unitName)
		if _, err := m.Fs.Stat(unitPath); err != nil {
			continue
		}
		return m.readSocketProperties(unitPath)
	}
	return nil, fmt.Errorf("%w: %s", ErrServiceNotFound, name)
}

func (m *SystemdFSSocketManager) readSocketUnit(name, unitPath string) (*SystemdSocket, error) {
	socket := &SystemdSocket{
		Name:      name,
		Installed: true,
	}

	// Check if masked (symlink to /dev/null)
	if lr, ok := m.Fs.(afero.LinkReader); ok {
		linkPath, err := lr.ReadlinkIfPossible(unitPath)
		if err == nil && linkPath == "/dev/null" {
			socket.Masked = true
			return socket, nil
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
			socket.Description = o.Value
		case o.Section == "Install":
			hasInstall = true
		}
	}
	socket.Static = !socket.Masked && !hasInstall

	return socket, nil
}

func (m *SystemdFSSocketManager) readSocketProperties(unitPath string) (map[string]string, error) {
	f, err := m.Fs.Open(unitPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	opts, err := unit.Deserialize(f)
	if err != nil {
		return nil, err
	}

	props := map[string]string{}
	var listenAddrs []string
	for _, o := range opts {
		if o.Section != "Socket" {
			continue
		}
		switch o.Name {
		case "ListenStream", "ListenDatagram", "ListenSequentialPacket", "ListenFIFO", "ListenNetlink", "ListenSpecial":
			listenAddrs = append(listenAddrs, o.Value)
		case "Accept":
			props["Accept"] = o.Value
		case "Service":
			props["Triggers"] = o.Value
		}
	}

	if len(listenAddrs) > 0 {
		props["Listen"] = strings.Join(listenAddrs, "\n")
	}

	// If Triggers/Service is not explicitly set, systemd defaults to <name>.service
	if props["Triggers"] == "" {
		base := path.Base(unitPath)
		props["Triggers"] = normalizeSystemdSocketName(base) + ".service"
	}

	return props, nil
}
