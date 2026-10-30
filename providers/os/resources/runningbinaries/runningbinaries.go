// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package runningbinaries lists the executables of running processes, finds
// the installed package that owns each one, and identifies the software and
// version from the file itself, without running it.
package runningbinaries

import (
	"errors"

	"go.mondoo.com/mql/llx"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// Binary is one executable that at least one running process was started from.
type Binary struct {
	// Path is the executable's path on the asset.
	Path string
	// ContentPath is where the running file's bytes are read from, when it
	// differs from Path: on Linux /proc/<pid>/exe, for a file a package
	// upgrade replaced or deleted at Path, which /proc still holds.
	ContentPath string
	// Pids of the processes started from the binary, in ascending order.
	Pids []int64
	// System is set for a file that ships with the operating system rather
	// than with an installed package (Windows: under %SystemRoot%; macOS: on
	// the system volume or under System Integrity Protection).
	System bool
	// VersionInfo is the Windows version resource of the file. Nil on Linux.
	VersionInfo *PEVersionInfo
}

// PEVersionInfo is the part of a Windows version resource that identifies
// the software a file belongs to.
type PEVersionInfo struct {
	ProductName    string
	ProductVersion string
	FileVersion    string
	CompanyName    string
	// FileDescription names the file itself, which a component of a larger
	// product, such as Windows, describes better than its ProductName.
	FileDescription string
}

// List returns the executables of the asset's running processes, one entry
// per file. A connection that cannot run commands (a container image, a
// disk snapshot) reaches no running system, so it has no running binaries.
func List(conn shared.Connection) ([]Binary, error) {
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return []Binary{}, nil
	}
	asset := conn.Asset()
	if asset == nil || asset.Platform == nil {
		return nil, errors.New("cannot list running binaries: no platform information")
	}
	switch {
	case asset.Platform.IsFamily("windows"):
		return listWindows(conn)
	case asset.Platform.IsFamily("linux"):
		return listLinux(conn)
	case asset.Platform.IsFamily("darwin"):
		return listDarwin(conn)
	default:
		return nil, llx.NotApplicable(errors.New("running binaries are only supported on Linux, macOS and Windows, not on " + asset.Platform.Name))
	}
}
