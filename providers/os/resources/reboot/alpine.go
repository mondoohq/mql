// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"fmt"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/packages"
)

// AlpineReboot reports a pending reboot when the installed kernel package
// differs from the running kernel.
//
// Alpine ships one kernel package per flavor (linux-virt, linux-lts,
// linux-edge, linux-rpi) and apk replaces it in place on upgrade, so the
// installed package always describes the kernel the next boot loads. The
// running kernel names its flavor in uname -r: `6.12.110-0-virt` is booted from
// linux-virt at version 6.12.110-r0.
//
// Checking whether /lib/modules/$(uname -r) is gone does not work. apk removes
// the old modules on upgrade but leaves the directory behind, because it still
// holds initramfs-suffix, a file no package owns (seen on Alpine 3.22 after
// upgrading linux-virt 6.12.110-r0 to 6.12.111-r0). In a container, where
// uname -r is the host's kernel and /lib/modules is absent, it would also
// report a pending reboot on every Alpine container.
type AlpineReboot struct {
	conn shared.Connection
}

func (s *AlpineReboot) Name() string {
	return "Alpine Kernel Package"
}

func (s *AlpineReboot) RebootPending() (bool, error) {
	// a static asset runs no kernel, so no reboot is pending
	if !s.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return false, nil
	}

	cmd, err := s.conn.RunCommand("uname -r")
	if err != nil {
		return false, err
	}
	if cmd.ExitStatus != 0 {
		return false, fmt.Errorf("could not read the running kernel version: %s", readTrimmed(cmd.Stderr))
	}
	out, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return false, err
	}
	running := strings.TrimSpace(string(out))

	pkgName, pkgVersion, ok := alpineKernelPackage(running)
	if !ok {
		// not a kernel Alpine built, e.g. the host kernel seen from a container
		return false, nil
	}

	installed, found, err := s.installedVersion(pkgName)
	if err != nil {
		return false, err
	}
	if !found {
		// no package for the running flavor: a container, or a kernel that
		// apk does not manage, and nothing apk installed is waiting to boot
		return false, nil
	}
	return installed != pkgVersion, nil
}

// installedVersion looks the package up in the apk database.
func (s *AlpineReboot) installedVersion(name string) (string, bool, error) {
	for _, path := range packages.ApkDbPaths {
		f, err := s.conn.FileSystem().Open(path)
		if err != nil {
			continue
		}
		pkgs := packages.ParseApkDbPackages(s.conn.Asset().Platform, f)
		f.Close()

		for i := range pkgs {
			if pkgs[i].Name == name {
				return pkgs[i].Version, true, nil
			}
		}
		return "", false, nil
	}
	return "", false, fmt.Errorf("could not read the apk database")
}

// alpineKernelPackage maps an Alpine kernel release `<ver>-<rel>-<flavor>`, as
// uname -r prints it, to the package it was installed from and that package's
// version: `linux-<flavor>` at `<ver>-r<rel>`.
func alpineKernelPackage(release string) (name string, version string, ok bool) {
	i := strings.LastIndexByte(release, '-')
	if i <= 0 || i == len(release)-1 {
		return "", "", false
	}
	flavor := release[i+1:]
	rest := release[:i]

	j := strings.LastIndexByte(rest, '-')
	if j <= 0 || j == len(rest)-1 {
		return "", "", false
	}
	ver, rel := rest[:j], rest[j+1:]
	for _, c := range rel {
		if c < '0' || c > '9' {
			return "", "", false
		}
	}
	return "linux-" + flavor, ver + "-r" + rel, true
}
