// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mount

import (
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type MountPoint struct {
	Device     string
	MountPoint string
	FSType     string
	Options    map[string]string
	// Unmounted is true for an access path that carries no file system, such
	// as a Windows drive letter assigned to an empty optical drive.
	Unmounted bool
	// Usage is the capacity of the mount when the listing itself carries it
	// (Windows). It is nil where capacity comes from df, or was not measured.
	Usage *DfEntry
}

type OperatingSystemMountManager interface {
	Name() string
	List() ([]MountPoint, error)
}

func ResolveManager(conn shared.Connection) (OperatingSystemMountManager, error) {
	var mm OperatingSystemMountManager

	pf := conn.Asset().Platform
	if pf == nil {
		return nil, errors.New("missing platform information")
	}

	if pf.IsFamily("windows") {
		mm = &WindowsMountManager{conn: conn}
	} else if pf.IsFamily("linux") {
		mm = &LinuxMountManager{conn: conn}
	} else if pf.IsFamily("unix") {
		mm = &UnixMountManager{conn: conn}
	}

	if mm == nil {
		return nil, errors.New("could not detect suitable mount manager for platform: " + pf.Name)
	}

	return mm, nil
}

type LinuxMountManager struct {
	conn shared.Connection
}

func (s *LinuxMountManager) Name() string {
	return "Linux Mount Manager"
}

func (s *LinuxMountManager) List() ([]MountPoint, error) {
	// `mount` carries the richest output, but plenty of hosts have a command
	// capability and no util-linux to answer with: the immutable and distroless
	// images in particular. /proc/mounts lists the same mounts, so reach for it
	// when the command cannot answer rather than failing the whole resource.
	if s.conn.Capabilities().Has(shared.Capability_RunCommand) {
		mounts, err := s.mountsFromCommand()
		if err == nil {
			return mounts, nil
		}
		if !s.conn.Capabilities().Has(shared.Capability_File) {
			return nil, err
		}
		log.Debug().Err(err).Msg("mql[mount]> could not read mounts with the mount command, reading them from the filesystem")
	}

	if s.conn.Capabilities().Has(shared.Capability_File) {
		return mountsFromFSLinux(s.conn.FileSystem())
	}

	return nil, errors.New("mount not supported for provided transport")
}

func (s *LinuxMountManager) mountsFromCommand() ([]MountPoint, error) {
	cmd, err := s.conn.RunCommand("mount")
	if err != nil {
		return nil, errors.Wrap(err, "could not run the mount command")
	}
	if cmd.ExitStatus != 0 {
		return nil, errors.Newf("the mount command exited with %d", cmd.ExitStatus)
	}

	mounts := ParseLinuxMountCmd(cmd.Stdout)
	// A running Linux host always has at least a root mount, so an empty result
	// means the command did not answer, not that nothing is mounted.
	if len(mounts) == 0 {
		return nil, errors.New("the mount command reported no mounts")
	}
	return mounts, nil
}

type UnixMountManager struct {
	conn shared.Connection
}

func (s *UnixMountManager) Name() string {
	return "Unix Mount Manager"
}

func (s *UnixMountManager) List() ([]MountPoint, error) {
	cmd, err := s.conn.RunCommand("mount")
	if err != nil {
		return nil, errors.Wrap(err, "could not run mount command")
	}
	// Without this the stderr of a failed mount command parses to an empty list
	// and reports as "nothing is mounted".
	if cmd.ExitStatus != 0 {
		return nil, errors.Newf("the mount command exited with %d", cmd.ExitStatus)
	}

	return ParseUnixMountCmd(cmd.Stdout), nil
}
