// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"errors"

	"go.mondoo.com/mql/v13/providers/os/connection/shared"
)

type OperatingSystemUpdate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Restart     bool   `json:"restart"`
	Format      string `json:"format"`
}

type OperatingSystemUpdateManager interface {
	Name() string
	List() ([]OperatingSystemUpdate, error)
}

// ResolveSystemUpdateManager uses the local system updated to ask for updates
func ResolveSystemUpdateManager(conn shared.Connection) (OperatingSystemUpdateManager, error) {
	var um OperatingSystemUpdateManager

	pf := conn.Asset().Platform

	// TODO: use OS family and select package manager
	switch pf.Name {
	case "opensuse", "sles", "opensuse-leap", "opensuse-tumbleweed", "opensuse-microos": // suse family
		um = &SuseUpdateManager{conn: conn}
	case "windows":
		um = &WindowsUpdateManager{conn: conn}
	case "macos":
		um = &MacosUpdateManager{conn: conn}
	default:
		return nil, errors.New("your platform is not supported by os updates resource")
	}
	return um, nil
}
