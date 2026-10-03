// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"io"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"

	"go.mondoo.com/mql/providers/core/resources/versions/rpm"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/packages"
)

// RpmNewestKernel works on all machines running rpm
type RpmNewestKernel struct {
	conn shared.Connection
}

func (s *RpmNewestKernel) Name() string {
	return "RPM Latest Kernel"
}

// rpmNeedsRestartingCmd asks needs-restarting (yum-utils on RHEL 7, dnf-utils
// / yum-utils on dnf hosts) whether the system needs a reboot. It answers yes
// for a newer kernel and also for core libraries and services updated since
// boot (glibc, systemd, openssl, linux-firmware, ...). LC_ALL=C keeps the
// verdict sentence untranslated.
const rpmNeedsRestartingCmd = "LC_ALL=C needs-restarting -r"

// rpmQueryKernelCmd lists the packages that provide "kernel": the kernel
// package on RHEL 7, kernel and kernel-core since RHEL 8, and only
// kernel-core on minimal Fedora images that don't install the metapackage.
const rpmQueryKernelCmd = "rpm -q --whatprovides kernel --queryformat '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}__%{VENDOR}__%{SUMMARY}__%{LICENSE}__%{INSTALLTIME}\n'"

// parseNeedsRestarting reads the verdict of `needs-restarting -r`. It exits 1
// and says "Reboot is required" when a reboot is needed, and exits 0 and says
// "Reboot should not be necessary" when not. Anything else (not installed, a
// dnf error, which also exits 1) is no verdict: ok is false.
func parseNeedsRestarting(exitStatus int, stdout string) (required bool, ok bool) {
	switch {
	case exitStatus == 1 && strings.Contains(stdout, "Reboot is required"):
		return true, true
	case exitStatus == 0 && strings.Contains(stdout, "Reboot should not be necessary"):
		return false, true
	default:
		return false, false
	}
}

func (s *RpmNewestKernel) RebootPending() (bool, error) {
	// if it is a static asset, no reboot is pending
	if !s.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return false, nil
	}

	// needs-restarting knows more than the kernel comparison below (core
	// library updates), so a reboot it asks for counts. Its "no" doesn't
	// overrule a newer installed kernel: it only looks at packages updated
	// after boot.
	if cmd, err := s.conn.RunCommand(rpmNeedsRestartingCmd); err == nil {
		out, _ := io.ReadAll(cmd.Stdout)
		if required, ok := parseNeedsRestarting(cmd.ExitStatus, string(out)); ok && required {
			return true, nil
		}
	}

	// get installed kernel version
	installedKernelCmd, err := s.conn.RunCommand(rpmQueryKernelCmd)
	if err != nil {
		return false, err
	}

	// `rpm -q` exits non-zero and prints "no package provides kernel" on
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
		cmp, err := parser.Compare(kernelReleaseOf(pkgs[i].Version, pkgs[i].Arch, kernelVersion), kernelVersion)
		if err != nil {
			return false, err
		}
		if cmp >= 1 {
			return true, nil
		}
	}
	return false, nil
}

// kernelReleaseOf turns a kernel package version into the shape uname -r
// reports, so the two compare release to release. uname -r never carries the
// rpm epoch, which Amazon Linux 2023 and 2027 kernels have (epoch 1 sorts
// above any running kernel), and on RHEL, Fedora and Amazon Linux it ends
// in the arch, which the package version doesn't. The arch is only appended
// when the running release has it, so a kernel built without it (linuxkit)
// is compared as is.
func kernelReleaseOf(pkgVersion, pkgArch, running string) string {
	if i := strings.IndexByte(pkgVersion, ':'); i >= 0 {
		pkgVersion = pkgVersion[i+1:]
	}
	if pkgArch != "" && strings.HasSuffix(running, "."+pkgArch) {
		pkgVersion += "." + pkgArch
	}
	return pkgVersion
}
