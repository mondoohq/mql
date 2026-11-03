// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
	"howett.net/plist"
)

// diskutilList is the part of `diskutil list -plist` that locates volumes.
// Each whole disk carries either partitions (a partition map), APFS volumes
// (a synthesized APFS container), or a filesystem of its own.
type diskutilList struct {
	AllDisksAndPartitions []diskutilListDisk `plist:"AllDisksAndPartitions"`
}

type diskutilListDisk struct {
	DeviceIdentifier string                  `plist:"DeviceIdentifier"`
	Content          string                  `plist:"Content"`
	VolumeName       *string                 `plist:"VolumeName"`
	Partitions       []diskutilListPartition `plist:"Partitions"`
	APFSVolumes      []diskutilListAPFSVol   `plist:"APFSVolumes"`
}

type diskutilListPartition struct {
	DeviceIdentifier string `plist:"DeviceIdentifier"`
	Content          string `plist:"Content"`
}

type diskutilListAPFSVol struct {
	DeviceIdentifier string                 `plist:"DeviceIdentifier"`
	MountedSnapshots []diskutilListSnapshot `plist:"MountedSnapshots"`
}

type diskutilListSnapshot struct {
	SnapshotBSD string `plist:"SnapshotBSD"`
}

// diskutilAPFSList is the part of `diskutil apfs list -plist` that carries
// the roles of each APFS volume, which `diskutil info -plist` does not report.
type diskutilAPFSList struct {
	Containers []struct {
		Volumes []struct {
			DeviceIdentifier string   `plist:"DeviceIdentifier"`
			Roles            []string `plist:"Roles"`
		} `plist:"Volumes"`
	} `plist:"Containers"`
}

// diskutilInfo is the part of `diskutil info -plist <device>` a
// macos.volume reports. Keys diskutil leaves out read as their zero value:
// an unencrypted HFS+ volume has no FileVault, Encryption or Locked key.
type diskutilInfo struct {
	DeviceIdentifier string `plist:"DeviceIdentifier"`
	VolumeName       string `plist:"VolumeName"`
	VolumeUUID       string `plist:"VolumeUUID"`
	MountPoint       string `plist:"MountPoint"`
	FilesystemType   string `plist:"FilesystemType"`
	FilesystemName   string `plist:"FilesystemName"`
	Internal         bool   `plist:"Internal"`
	BusProtocol      string `plist:"BusProtocol"`
	OSInternalMedia  bool   `plist:"OSInternalMedia"`
	Encryption       bool   `plist:"Encryption"`
	FileVault        bool   `plist:"FileVault"`
	Locked           bool   `plist:"Locked"`
}

// diskutilVolumeRef is a volume found in `diskutil list -plist`.
type diskutilVolumeRef struct {
	deviceIdentifier string
	// partitionType is the partition map's content type, empty for APFS
	// volumes and for a filesystem that fills a whole disk.
	partitionType string
	apfs          bool
}

// macosVolume holds the values of one macos.volume.
type macosVolume struct {
	deviceIdentifier string
	name             string
	uuid             string
	mountPoint       string
	filesystemType   string
	filesystem       string
	partitionType    string
	roles            []string
	internal         bool
	busProtocol      string
	osInternal       bool
	encrypted        bool
	fileVault        bool
	locked           bool
}

// parseDiskutilList returns the volumes `diskutil list -plist` reports, in
// its order. APFS physical stores and CoreStorage physical volumes are
// partitions that hold a container, not a filesystem, and are skipped: the
// container's volumes are listed under their own synthesized disk. Mounted
// APFS snapshots (the sealed system snapshot mounted at /) are listed among
// the APFS volumes and are skipped too.
func parseDiskutilList(data []byte) ([]diskutilVolumeRef, error) {
	var list diskutilList
	if _, err := plist.Unmarshal(data, &list); err != nil {
		return nil, err
	}

	snapshots := map[string]struct{}{}
	for _, disk := range list.AllDisksAndPartitions {
		for _, vol := range disk.APFSVolumes {
			for _, snap := range vol.MountedSnapshots {
				snapshots[snap.SnapshotBSD] = struct{}{}
			}
		}
	}

	refs := []diskutilVolumeRef{}
	for _, disk := range list.AllDisksAndPartitions {
		for _, part := range disk.Partitions {
			if isContainerPartition(part.Content) {
				continue
			}
			refs = append(refs, diskutilVolumeRef{
				deviceIdentifier: part.DeviceIdentifier,
				partitionType:    part.Content,
			})
		}
		for _, vol := range disk.APFSVolumes {
			if _, ok := snapshots[vol.DeviceIdentifier]; ok {
				continue
			}
			refs = append(refs, diskutilVolumeRef{
				deviceIdentifier: vol.DeviceIdentifier,
				apfs:             true,
			})
		}
		// A filesystem on the whole disk, without a partition map, such as
		// an HFS+ CoreStorage logical volume.
		if len(disk.Partitions) == 0 && len(disk.APFSVolumes) == 0 && disk.VolumeName != nil {
			refs = append(refs, diskutilVolumeRef{deviceIdentifier: disk.DeviceIdentifier})
		}
	}
	return refs, nil
}

func isContainerPartition(content string) bool {
	return strings.HasPrefix(content, "Apple_APFS") || content == "Apple_CoreStorage"
}

// parseDiskutilAPFSRoles maps each APFS volume's device identifier to its
// roles, from `diskutil apfs list -plist`.
func parseDiskutilAPFSRoles(data []byte) (map[string][]string, error) {
	var list diskutilAPFSList
	if _, err := plist.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	roles := map[string][]string{}
	for _, c := range list.Containers {
		for _, v := range c.Volumes {
			roles[v.DeviceIdentifier] = v.Roles
		}
	}
	return roles, nil
}

func parseDiskutilInfo(data []byte) (diskutilInfo, error) {
	var info diskutilInfo
	_, err := plist.Unmarshal(data, &info)
	return info, err
}

func newMacosVolume(ref diskutilVolumeRef, info diskutilInfo, roles []string) macosVolume {
	if roles == nil {
		roles = []string{}
	}
	return macosVolume{
		deviceIdentifier: ref.deviceIdentifier,
		name:             info.VolumeName,
		uuid:             info.VolumeUUID,
		mountPoint:       info.MountPoint,
		filesystemType:   info.FilesystemType,
		filesystem:       info.FilesystemName,
		partitionType:    ref.partitionType,
		roles:            roles,
		internal:         info.Internal,
		busProtocol:      info.BusProtocol,
		osInternal:       info.OSInternalMedia,
		encrypted:        info.Encryption,
		fileVault:        info.FileVault,
		locked:           info.Locked,
	}
}

// systemAPFSRoles are the APFS roles of volumes that support booting,
// recovery, updates, or the hardware, and hold no user data. A role not in
// this list, or no role, counts as user storage, so an unknown role is
// assessed rather than skipped.
var systemAPFSRoles = []string{"Preboot", "Recovery", "VM", "Update", "xART", "Hardware", "Installer"}

// systemPartitionTypes are partition types that hold firmware or recovery
// files: the EFI system partition, and the Recovery HD of HFS+ systems.
var systemPartitionTypes = []string{"EFI", "Apple_Boot"}

func (v macosVolume) userStorage() bool {
	if v.osInternal || slices.Contains(systemPartitionTypes, v.partitionType) {
		return false
	}
	for _, role := range v.roles {
		if slices.Contains(systemAPFSRoles, role) {
			return false
		}
	}
	return true
}

func initMacosVolumes(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return args, nil, nil
	}
	if pf := conn.Asset().GetPlatform(); pf != nil && !pf.IsFamily("darwin") {
		return nil, nil, llx.NotApplicable(errors.New("macos.volumes is only available on macOS"))
	}
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, nil, llx.NotApplicable(errors.New("macos.volumes needs a running system, and this connection cannot run commands"))
	}
	return args, nil, nil
}

func (m *mqlMacosVolumes) id() (string, error) {
	return "macos.volumes", nil
}

func (m *mqlMacosVolumes) diskutil(args string) ([]byte, error) {
	o, err := CreateResource(m.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("diskutil " + args),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return nil, exit.Error
	}
	if exit.Data != 0 {
		msg := strings.TrimSpace(cmd.GetStderr().Data)
		if msg == "" {
			msg = strings.TrimSpace(cmd.GetStdout().Data)
		}
		return nil, fmt.Errorf("diskutil %s failed: %s", args, msg)
	}
	stdout := cmd.GetStdout()
	if stdout.Error != nil {
		return nil, stdout.Error
	}
	return []byte(stdout.Data), nil
}

// list reads every volume from `diskutil list -plist`, its roles from
// `diskutil apfs list -plist`, and its details from `diskutil info -plist`.
// A volume diskutil cannot describe fails the list instead of being left
// out, so a check over all volumes never passes on a partial list.
func (m *mqlMacosVolumes) list() ([]any, error) {
	out, err := m.diskutil("list -plist")
	if err != nil {
		return nil, err
	}
	refs, err := parseDiskutilList(out)
	if err != nil {
		return nil, llx.MalformedData(errors.New("could not parse diskutil list output: " + err.Error()))
	}

	roles := map[string][]string{}
	if slices.ContainsFunc(refs, func(r diskutilVolumeRef) bool { return r.apfs }) {
		out, err := m.diskutil("apfs list -plist")
		if err != nil {
			return nil, err
		}
		roles, err = parseDiskutilAPFSRoles(out)
		if err != nil {
			return nil, llx.MalformedData(errors.New("could not parse diskutil apfs list output: " + err.Error()))
		}
	}

	res := make([]any, 0, len(refs))
	for _, ref := range refs {
		out, err := m.diskutil("info -plist " + ref.deviceIdentifier)
		if err != nil {
			return nil, err
		}
		info, err := parseDiskutilInfo(out)
		if err != nil {
			return nil, llx.MalformedData(fmt.Errorf("could not parse diskutil info output for %s: %w", ref.deviceIdentifier, err))
		}
		vol := newMacosVolume(ref, info, roles[ref.deviceIdentifier])

		r, err := CreateResource(m.MqlRuntime, "macos.volume", map[string]*llx.RawData{
			"__id":             llx.StringData("macos.volume/" + vol.deviceIdentifier),
			"deviceIdentifier": llx.StringData(vol.deviceIdentifier),
			"name":             llx.StringData(vol.name),
			"uuid":             llx.StringData(vol.uuid),
			"mountPoint":       llx.StringData(vol.mountPoint),
			"filesystemType":   llx.StringData(vol.filesystemType),
			"filesystem":       llx.StringData(vol.filesystem),
			"partitionType":    llx.StringData(vol.partitionType),
			"roles":            llx.ArrayData(llx.TArr2Raw(vol.roles), types.String),
			"internal":         llx.BoolData(vol.internal),
			"busProtocol":      llx.StringData(vol.busProtocol),
			"osInternal":       llx.BoolData(vol.osInternal),
			"userStorage":      llx.BoolData(vol.userStorage()),
			"encrypted":        llx.BoolData(vol.encrypted),
			"fileVault":        llx.BoolData(vol.fileVault),
			"locked":           llx.BoolData(vol.locked),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}
