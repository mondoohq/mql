// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

const (
	WindowsTestComponentServicesReboot = "Test-Path -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'"
	WindowsTestWsusReboot              = "Test-Path -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'"
)

// WinReboot checks if the windows instance requires a reboot
// Excellent resources:
// https://devblogs.microsoft.com/scripting/determine-pending-reboot-statuspowershell-style-part-1/
// https://devblogs.microsoft.com/scripting/determine-pending-reboot-statuspowershell-style-part-2/
// Brian Wilhite powershell implementation:
// https://github.com/bcwilhite/PendingReboot
type WinReboot struct {
	conn shared.Connection
}

func (s *WinReboot) Name() string {
	return "Windows Reboot"
}

func (s *WinReboot) RebootPending() (bool, error) {
	isRebootrequired := false

	// Query the Component Based Servicing Reg Key
	cmd, err := s.conn.RunCommand(powershell.Wrap(WindowsTestComponentServicesReboot))
	if err != nil {
		return false, err
	}

	content, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return false, err
	}

	if strings.TrimSpace(strings.ToLower(string(content))) == "true" {
		isRebootrequired = true
	}

	// Query WUAU from the registry
	cmd, err = s.conn.RunCommand(powershell.Wrap(WindowsTestWsusReboot))
	if err != nil {
		return false, err
	}

	content, err = io.ReadAll(cmd.Stdout)
	if err != nil {
		return false, err
	}

	if strings.TrimSpace(strings.ToLower(string(content))) == "true" {
		isRebootrequired = true
	}

	// Query PendingFileRenameOperations from the registry
	// Note: we are not using it since its also used by non-OS specific apps

	return isRebootrequired, nil
}
