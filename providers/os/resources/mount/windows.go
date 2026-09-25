// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mount

import (
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

type WindowsMountManager struct {
	conn shared.Connection
}

func (s *WindowsMountManager) Name() string {
	return "Windows Mount Manager"
}

// List reads the volume table of a running Windows system. The table only
// exists at run time: an image or a mounted disk of a Windows system carries
// no record of which volumes are attached where, so a connection that cannot
// run commands cannot answer, and says so rather than reporting no mounts.
func (s *WindowsMountManager) List() ([]MountPoint, error) {
	if !s.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, llx.NotApplicable(errors.New("the Windows volume table can only be read from a running system; this connection cannot run commands"))
	}
	vols, err := windows.GetVolumes(s.conn)
	if err != nil {
		return nil, err
	}
	return WindowsMountPoints(vols), nil
}

// WindowsMountPoints turns volumes into mount points, one per access path, so
// a volume mounted at both a drive letter and a folder is found at either.
func WindowsMountPoints(vols []windows.Volume) []MountPoint {
	res := []MountPoint{}
	for _, v := range vols {
		for _, p := range v.AccessPaths {
			mp := MountPoint{
				Device:     v.DeviceID,
				MountPoint: p,
				FSType:     v.FileSystem,
				// Each mount point gets its own map: the resource layer
				// converts it, and a shared map would alias between them.
				Options:   windowsVolumeOptions(v),
				Unmounted: v.FileSystem == "",
			}
			if v.Capacity != nil && v.FreeSpace != nil {
				mp.Usage = &DfEntry{
					Filesystem: v.DeviceID,
					Size:       *v.Capacity,
					Used:       *v.Capacity - *v.FreeSpace,
					Available:  *v.FreeSpace,
					MountedOn:  p,
				}
			}
			res = append(res, mp)
		}
	}
	return res
}

// windowsVolumeOptions reports what Windows says about a volume. The flags
// appear only when true, the way a Linux flag option appears only when set;
// the two valued keys carry the drive type and the label.
func windowsVolumeOptions(v windows.Volume) map[string]string {
	opts := map[string]string{"driveType": v.DriveType}
	if v.Label != "" {
		opts["label"] = v.Label
	}
	if v.BootVolume {
		opts["bootVolume"] = ""
	}
	if v.SystemVolume {
		opts["systemVolume"] = ""
	}
	if v.PageFile {
		opts["pageFile"] = ""
	}
	if v.Compressed {
		opts["compressed"] = ""
	}
	return opts
}
