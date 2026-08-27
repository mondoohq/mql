// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"fmt"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// zypperRebootNeededExit is what `zypper needs-rebooting` exits with when core
// libraries or the kernel have been updated since the machine booted. zypper
// documents it as ZYPPER_EXIT_INF_REBOOT_NEEDED; a clean check exits 0.
const zypperRebootNeededExit = 103

// ZypperNeedsRebooting asks zypper whether anything updated since boot needs
// the machine restarted.
//
// The rpm-newest-kernel comparison the redhat family uses does not carry over:
// SUSE names the kernel package for its flavour (kernel-default,
// kernel-azure, ...), so `rpm -q kernel` reports nothing installed and the
// comparison would answer "no reboot pending" on every SUSE host.
type ZypperNeedsRebooting struct {
	conn shared.Connection
}

func (s *ZypperNeedsRebooting) Name() string {
	return "Zypper Needs Rebooting"
}

func (s *ZypperNeedsRebooting) RebootPending() (bool, error) {
	// a static asset cannot be asked, and has not booted anything either
	if !s.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return false, nil
	}

	cmd, err := s.conn.RunCommand("zypper --non-interactive needs-rebooting")
	if err != nil {
		return false, err
	}

	switch cmd.ExitStatus {
	case 0:
		return false, nil
	case zypperRebootNeededExit:
		return true, nil
	default:
		return false, fmt.Errorf("zypper needs-rebooting exited %d: %s",
			cmd.ExitStatus, readTrimmed(cmd.Stderr))
	}
}

func readTrimmed(r io.Reader) string {
	if r == nil {
		return ""
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
