// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type Reboot interface {
	Name() string
	RebootPending() (bool, error)
}

func New(conn shared.Connection) (Reboot, error) {
	pf := conn.Asset().Platform

	switch {
	// NixOS is in the linux family and none of the others, and it carries no
	// package manager whose reboot marker the cases below look for.
	case pf.Name == "nixos":
		return newNixosReboot(conn), nil
	case pf.IsFamily("debian"):
		return &DebianReboot{conn: conn}, nil
	case pf.IsFamily("redhat") || pf.IsFamily("euler") || pf.Name == "amazonlinux":
		return &RpmNewestKernel{conn: conn}, nil
	case pf.IsFamily("suse"):
		return &ZypperNeedsRebooting{conn: conn}, nil
	case pf.Name == "alpine":
		return &AlpineReboot{conn: conn}, nil
	case pf.Name == "freebsd":
		return &FreebsdReboot{conn: conn}, nil
	case pf.IsFamily(inventory.FAMILY_WINDOWS):
		return &WinReboot{conn: conn}, nil
	// Apple reports a prepared update that waits on a restart only to an MDM
	// server (the softwareupdate.install-state status item). Nothing on the Mac
	// itself documents that state, so the question cannot be answered locally.
	case pf.Name == "macos":
		return nil, llx.NotApplicable(errors.New("macOS reports a pending restart only to an MDM server, it cannot be read from the system"))
	default:
		return nil, errors.New("your platform is not supported by reboot resource")
	}
}
