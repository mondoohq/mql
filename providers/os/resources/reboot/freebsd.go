// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"fmt"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// freebsdKernelVersionsCommand prints the version of the installed kernel (the
// one the loader boots next) and then the version of the running kernel.
// freebsd-version -r does the latter only from 13.0 on; uname -r reads the
// same kern.osrelease on every release.
const freebsdKernelVersionsCommand = "freebsd-version -k && uname -r"

// FreebsdReboot reports a pending reboot when the installed kernel differs
// from the running one. The userland version (freebsd-version -u) plays no
// part: freebsd-update often patches only userland, and then the kernel
// version stays behind without a reboot being needed.
type FreebsdReboot struct {
	conn shared.Connection
}

func (s *FreebsdReboot) Name() string {
	return "FreeBSD Reboot"
}

func (s *FreebsdReboot) RebootPending() (bool, error) {
	// if it is a static asset, no reboot is pending
	if !s.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return false, nil
	}

	cmd, err := s.conn.RunCommand(freebsdKernelVersionsCommand)
	if err != nil {
		return false, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return false, fmt.Errorf("could not read the installed and running kernel versions: %s", strings.TrimSpace(string(stderr)))
	}
	out, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return false, err
	}
	return freebsdKernelChanged(string(out))
}

// freebsdKernelChanged reads the output of freebsdKernelVersionsCommand.
func freebsdKernelChanged(out string) (bool, error) {
	versions := strings.Fields(out)
	if len(versions) != 2 {
		return false, fmt.Errorf("unexpected kernel version output: %q", out)
	}
	return versions[0] != versions[1], nil
}
