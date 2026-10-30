// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"fmt"
	"io"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/packages"
)

const (
	SuseOSUpdateFormat = "suse"
)

type SuseUpdateManager struct {
	conn shared.Connection
}

func (sum *SuseUpdateManager) Name() string {
	return "Suse Update Manager"
}

func (sum *SuseUpdateManager) Format() string {
	return SuseOSUpdateFormat
}

func (sum *SuseUpdateManager) List() ([]OperatingSystemUpdate, error) {
	cmd, err := sum.conn.RunCommand("zypper -n --xmlout list-updates -t patch")
	if err != nil {
		return nil, fmt.Errorf("could not read zypper package list")
	}
	return ParseZypperPatches(cmd.Stdout)
}

// ParseZypperPatches reads the operating system patches for Suse
func ParseZypperPatches(input io.Reader) ([]OperatingSystemUpdate, error) {
	zypper, err := packages.ParseZypper(input)
	if err != nil {
		return nil, err
	}

	// While a patch for the package manager itself (libzypp, zypper) is
	// pending, zypper lists only those patches in <update-list> and moves every
	// other needed patch to <blocked-update-list>, because it installs the
	// package manager stack first. The blocked patches are still pending.
	all := append(zypper.Updates, zypper.Blocked...)

	var updates []OperatingSystemUpdate
	// filter for kind patch
	for _, u := range all {
		if u.Kind != "patch" {
			continue
		}

		restart := false
		if u.Restart == "true" {
			restart = true
		}

		updates = append(updates, OperatingSystemUpdate{
			ID:          u.Edition,
			Name:        u.Name,
			Severity:    u.Severity,
			Restart:     restart,
			Category:    u.Category,
			Description: u.Description,
			Format:      SuseOSUpdateFormat,
		})
	}

	return updates, nil
}
