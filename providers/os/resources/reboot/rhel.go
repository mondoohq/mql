// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"io"
	"strings"

	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"

	"go.mondoo.com/mql/v13/providers/core/resources/versions/rpm"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/providers/os/resources/packages"
)

// RpmNewestKernel works on all machines running rpm
type RpmNewestKernel struct {
	conn shared.Connection
}

func (s *RpmNewestKernel) Name() string {
	return "RPM Latest Kernel"
}

func (s *RpmNewestKernel) RebootPending() (bool, error) {
	// if it is a static asset, no reboot is pending
	if !s.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return false, nil
	}

	// get installed kernel version
	installedKernelCmd, err := s.conn.RunCommand("rpm -q kernel --queryformat '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}__%{VENDOR}__%{SUMMARY}__%{LICENSE}__%{INSTALLTIME}\n'")
	if err != nil {
		return false, err
	}

	// `rpm -q` exits non-zero and prints "package kernel is not installed" on
	// stdout when there is no kernel package, which is the normal case in a
	// container. Feeding that sentence to the package parser made it report a
	// dropped package line, so every container scan warned that packages were
	// missing from the inventory when nothing was.
	if installedKernelCmd.ExitStatus != 0 {
		return false, nil
	}

	var pf *inventory.Platform
	if s.conn.Asset() != nil {
		pf = s.conn.Asset().Platform
	}

	pkgs := packages.ParseRpmPackages(pf, installedKernelCmd.Stdout)
	// this case is valid in container
	if len(pkgs) == 0 {
		return false, nil
	}

	// check running kernel version
	unamerCmd, err := s.conn.RunCommand("uname -r")
	if err != nil {
		return false, err
	}

	unameR, err := io.ReadAll(unamerCmd.Stdout)
	if err != nil {
		return false, err
	}

	// check if any kernel is newer
	kernelVersion := strings.TrimSpace(string(unameR))

	var parser rpm.Parser

	for i := range pkgs {
		cmp, err := parser.Compare(pkgs[i].Version, kernelVersion)
		if err != nil {
			return false, err
		}
		if cmp >= 1 {
			return true, nil
		}
	}
	return false, nil
}
