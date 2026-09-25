// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package linux

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/snapshot"
	"go.mondoo.com/mql/providers/os/mountedfs"
	"go.mondoo.com/mql/providers/os/resources/fstab"
)

const (
	LunOption                   = "lun"
	LunsOption                  = "luns"
	DeviceName                  = "device-name"
	DeviceNames                 = "device-names"
	MountAllPartitions          = "mount-all-partitions"
	IncludeMounted              = "include-mounted"
	SkipAttemptExpandPartitions = "skip-attempt-expand-partitions"
)

type LinuxDeviceManager struct {
	volumeMounter snapshot.VolumeMounter
	cmdRunner     *snapshot.LocalCommandRunner
	opts          map[string]string
}

func NewLinuxDeviceManager(shell []string, opts map[string]string) (*LinuxDeviceManager, error) {
	if err := validateOpts(opts); err != nil {
		return nil, err
	}

	return &LinuxDeviceManager{
		volumeMounter: snapshot.NewVolumeMounter(shell),
		cmdRunner:     &snapshot.LocalCommandRunner{Shell: shell},
		opts:          opts,
	}, nil
}

func (d *LinuxDeviceManager) Name() string {
	return "linux"
}

func (d *LinuxDeviceManager) IdentifyMountTargets(opts map[string]string) ([]*snapshot.Partition, error) {
	if err := validateOpts(opts); err != nil {
		return nil, err
	}

	deviceNames := []string{}
	luns, err := getLunsFromOpts(opts)
	if err != nil {
		return nil, err
	}
	for _, l := range luns {
		devices, err := d.identifyDeviceViaLun(l)
		if err != nil {
			return nil, err
		}
		for _, device := range devices {
			deviceNames = append(deviceNames, device.Name)
		}
	}

	if opts[DeviceNames] != "" {
		deviceNames = strings.Split(opts[DeviceNames], ",")
	}
	if opts[DeviceName] != "" {
		deviceNames = append(deviceNames, opts[DeviceName])
	}

	var partitions []*snapshot.Partition
	var errs []error
	mountAll := opts[MountAllPartitions] == "true"
	includeMounted := opts[IncludeMounted] == "true"
	for _, deviceName := range deviceNames {
		partitionsForDevice, err := d.identifyViaDeviceName(deviceName, mountAll, includeMounted)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		partitions = append(partitions, partitionsForDevice...)
	}

	if len(partitions) == 0 {
		errs = append(errs, errors.New("no partitions found"))
		return partitions, errors.Join(errs...)
	}

	return partitions, errors.Join(errs...)
}

// tries to handle cases like
// 1. reconstructing partitions from fstab
// 2. expanding partitions that are part of an ostree (we need to find the root dir)
func (d *LinuxDeviceManager) attemptExpandAndMountPartitions(partitions []*snapshot.Partition) ([]*snapshot.MountedPartition, bool, error) {
	log.Debug().Msg("attempting to expand partitions infos")

	fstabEntries, err := d.hintFsTypes(partitions)
	if err != nil {
		log.Warn().Err(err).Msg("could not find fstab")
		return nil, false, nil
	}
	if len(fstabEntries) == 0 {
		log.Debug().Msg("no fstab entries found, skipping mount with fstab")
		return nil, false, nil
	}

	log.Debug().Any("fstab", fstabEntries).Msg("fstab entries found")

	mounted, err := d.mountWithFstab(partitions, fstabEntries)
	if err != nil {
		log.Error().Err(err).Msg("unable to mount partitions with fstab")
		d.UnmountAndClose()
		return nil, true, err
	}

	return mounted, true, nil
}

func (d *LinuxDeviceManager) hintFsTypes(partitions []*snapshot.Partition) ([]fstab.Entry, error) {
	for _, partition := range partitions {
		entries, ostree, err := d.hintPartitionFsType(partition)
		if err != nil {
			log.Warn().Err(err).Str("device", partition.Name).Msg("unable to hint fstab entries")
			continue
		}
		if entries != nil {
			log.Debug().Str("device", partition.Name).Msg("fstab entries found")
			return entries, nil
		}
		if ostree != "" {
			partition.RootPath = ostree
		}
	}
	return nil, nil
}

func (d *LinuxDeviceManager) hintPartitionFsType(partition *snapshot.Partition) ([]fstab.Entry, string, error) {
	mounted, err := d.volumeMounter.Mount(partition.ToDefaultMountInput())
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if err := d.volumeMounter.Umount(mounted); err != nil {
			log.Warn().Err(err).Str("device", partition.Name).Msg("unable to unmount partition")
		}
	}()

	entries, err := d.attemptFindFstab(mounted.MountPoint)
	if err != nil {
		return nil, "", err
	}
	if entries != nil {
		return entries, "", nil
	}

	if match := d.attemptFindOSTreeRoot(mounted.MountPoint, partition.Name); match != "" {
		trimmed := strings.TrimPrefix(match, mounted.MountPoint)
		log.Debug().Str("device", partition.Name).Str("ostree", trimmed).Msg("ostree found")
		return nil, trimmed, nil
	}

	// no fstab/ostree found, return empty entries
	return nil, "", nil
}

func (d *LinuxDeviceManager) attemptFindFstab(dir string) ([]fstab.Entry, error) {
	cmd, err := d.cmdRunner.RunCommand(fmt.Sprintf("find %s -type f -wholename '*/etc/fstab'", dir))
	if err != nil {
		log.Error().Err(err).Msg("error searching for fstab")
		return nil, nil
	}

	out, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		log.Error().Err(err).Msg("error reading find output")
		return nil, nil
	}

	if l := len(strings.Split(string(out), "\n")); l > 2 {
		log.Debug().Bytes("find", out).Msg("fstab not found, too many results")
		return nil, nil
	} else if l < 2 {
		log.Debug().Bytes("find", out).Msg("fstab not found, no results")
		return nil, nil
	}

	mnt, fstabPath := path.Split(strings.TrimSpace(string(out)))
	fstabFile, err := afero.ReadFile(
		mountedfs.NewMountedFs(mnt),
		path.Base(fstabPath))
	if err != nil {
		log.Error().Err(err).Msg("error reading fstab")
		return nil, nil
	}

	return fstab.Parse(bytes.NewReader(fstabFile))
}

func (d *LinuxDeviceManager) attemptFindOSTreeRoot(dir string, partitionName string) string {
	log.Debug().Str("device", partitionName).Str("path", dir).Msg("attempting to find ostree")

	info, err := os.Stat(path.Join(dir, "ostree"))
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}

		log.Error().Err(err).Str("device", partitionName).Str("path", dir).Msg("unable to stat ostree")
		return ""
	}

	if !info.IsDir() {
		log.Warn().Str("device", partitionName).Str("path", dir).Msg("ostree is not a directory")
		return ""
	}

	entries, err := os.ReadDir(path.Join(dir, "ostree"))
	if err != nil {
		log.Error().Err(err).Str("device", partitionName).Str("path", dir).Msg("unable to read ostree directory")
		return ""
	}

	entries = slices.DeleteFunc(entries, func(entry os.DirEntry) bool {
		if entry.Type().Type() != os.ModeSymlink {
			return true
		}

		trimmed := strings.TrimPrefix(entry.Name(), "boot.")
		if trimmed == entry.Name() {
			return true
		}

		_, err := strconv.Atoi(trimmed)
		return err != nil
	})

	if len(entries) == 0 {
		log.Debug().Str("device", partitionName).Str("path", dir).Msg("no ostree entries")
		return ""
	}
	if len(entries) > 1 {
		slices.SortFunc(entries, func(a, b os.DirEntry) int {
			aIndex, _ := strconv.Atoi(strings.TrimPrefix(a.Name(), "boot."))
			bIndex, _ := strconv.Atoi(strings.TrimPrefix(b.Name(), "boot."))
			return aIndex - bIndex
		})
	}

	log.Debug().Str("device", partitionName).Str("path", dir).Str("boot1", entries[0].Name()).Msg("found ostree deployment")
	boot1, err := os.Readlink(path.Join(dir, "ostree", entries[0].Name()))
	if err != nil {
		log.Error().Err(err).Str("device", partitionName).Msg("unable to readlink boot.1")
		return ""
	}

	matches, err := filepath.Glob(path.Join(dir, "ostree", boot1, "*", "*", "0"))
	if err != nil {
		log.Error().Err(err).Str("device", partitionName).Msg("unable to glob ostree")
		return ""
	}

	if len(matches) == 0 {
		log.Debug().Str("device", partitionName).Str("path", dir).Msg("no ostree matches")
		return ""
	} else if len(matches) > 1 {
		log.Debug().Str("device", partitionName).Str("path", dir).Msg("multiple ostree matches")
	}

	match := matches[0]
	log.Debug().Str("matches", match).Str("device", partitionName).Msg("ostree match found")
	return match
}

// mountWithFstab mounts partitions adjusting the mountpoint and mount options according to the discovered fstab entries
func (d *LinuxDeviceManager) mountWithFstab(partitions []*snapshot.Partition, entries []fstab.Entry) ([]*snapshot.MountedPartition, error) {
	// sort the entries by the length of the mountpoint, so we can mount the top level partitions first
	sort.Slice(entries, func(i, j int) bool {
		return snapshot.PathDepth(entries[i].Mountpoint) < snapshot.PathDepth(entries[j].Mountpoint)
	})

	mps := []*snapshot.MountedPartition{}
	rootScanDir := ""
	for _, entry := range entries {
		partition := getPartitionForFsTab(partitions, entry)
		if partition == nil {
			log.Debug().Str("device", entry.Device).Msg("no partition found for fstab entry")
			continue
		}

		log.Debug().
			Str("device", partition.Name).
			Str("guest-mountpoint", entry.Mountpoint).
			Msg("partition matches fstab entry")

		mountDir := ""
		if rootScanDir != "" {
			mountDir = path.Join(rootScanDir, entry.Mountpoint)
		}

		log.Debug().Str("device", partition.Name).
			Strs("options", entry.Options).
			Any("mount-dir", mountDir).
			Msg("mounting partition as subvolume")
		mp, err := d.volumeMounter.Mount(partition.ToMountInput(entry.Options, mountDir))
		if err != nil {
			log.Error().Err(err).Str("device", partition.Name).Msg("unable to mount partition")
			return nil, err
		}

		if entry.Mountpoint == "/" {
			rootScanDir = mp.MountPoint
		}
		mps = append(mps, mp)
	}
	return mps, nil
}

func getPartitionForFsTab(partitions []*snapshot.Partition, entry fstab.Entry) *snapshot.Partition {
	for _, partition := range partitions {
		if cmpPartition2Fstab(partition, entry) {
			log.Debug().Str("device", partition.Name).Msg("found partition for fstab entry")
			return partition
		}
	}
	return nil
}

func cmpPartition2Fstab(partition *snapshot.Partition, entry fstab.Entry) bool {
	// Edge case: fstab entry is a symlink to a device mapper device (LVM2)
	if strings.HasPrefix(entry.Device, "/dev/mapper/") {
		return entry.Device == partition.Name
	}

	parts := strings.Split(entry.Device, "=")
	if len(parts) != 2 {
		log.Warn().Str("device", entry.Device).Msg("possibly invalid fstab entry, skipping")
		return false
	}

	if parts[1] == "" {
		log.Warn().Str("device", entry.Device).Msg("possibly invalid fstab entry, skipping")
		return false
	}

	switch parts[0] {
	case "UUID":
		return partition.Uuid == parts[1]
	case "LABEL":
		return partition.Label == parts[1]
	case "PARTUUID":
		return partition.PartUuid == parts[1]
	default:
		log.Warn().Str("device", entry.Device).Msg("couldn't identify fstab device")
		return false
	}
}

func (d *LinuxDeviceManager) Mount(partitions []*snapshot.Partition) ([]*snapshot.MountedPartition, error) {
	res := []*snapshot.MountedPartition{}
	if d.opts[SkipAttemptExpandPartitions] != "true" {
		mps, ok, err := d.attemptExpandAndMountPartitions(partitions)
		if ok {
			return mps, err
		}
	}

	for _, partition := range partitions {
		mounted, err := d.volumeMounter.Mount(partition.ToDefaultMountInput())
		if err != nil {
			log.Error().Err(err).Str("device", partition.Name).Msg("unable to mount partition")
			continue
		}
		res = append(res, mounted)
	}
	return res, nil
}

func (d *LinuxDeviceManager) UnmountAndClose() {
	log.Debug().Msg("closing linux device manager")
	if d == nil {
		return
	}

	if d.volumeMounter != nil {
		err := d.volumeMounter.UnmountAll()
		if err != nil {
			log.Error().Err(err).Msg("unable to unmount volume")
		}
		err = d.volumeMounter.RemoveTempScanDir()
		if err != nil {
			log.Error().Err(err).Msg("unable to remove dir")
		}
	}
}

// validates the options provided to the device manager
// we cannot have both LUN and device name provided, those are mutually exclusive
func validateOpts(opts map[string]string) error {
	// this is needed only for the validation purposes
	deviceNamesPresent := opts[DeviceName] != "" || opts[DeviceNames] != ""
	lunsPresent := opts[LunOption] != "" || opts[LunsOption] != ""
	mountAll := opts[MountAllPartitions] == "true"

	if deviceNamesPresent && lunsPresent {
		return errors.New("both lun and device names provided")
	}

	if !deviceNamesPresent && !lunsPresent {
		return errors.New("either lun or device names must be provided")
	}

	if mountAll && !deviceNamesPresent && !lunsPresent {
		return errors.New("mount-all-partitions requires device names or luns")
	}

	return nil
}

func getLunsFromOpts(opts map[string]string) ([]int, error) {
	luns := []int{}
	if opts[LunOption] != "" {
		lun, err := strconv.Atoi(opts[LunOption])
		if err != nil {
			return nil, err
		}
		luns = append(luns, lun)
	}
	if opts[LunsOption] != "" {
		vals := strings.Split(opts[LunsOption], ",")
		for _, l := range vals {
			lun, err := strconv.Atoi(l)
			if err != nil {
				return nil, err
			}
			luns = append(luns, lun)
		}
	}
	return luns, nil
}

func (c *LinuxDeviceManager) identifyDeviceViaLun(lun int) ([]snapshot.BlockDevice, error) {
	log.Debug().Int("lun", lun).Msg("identifying devices via LUN")
	scsiDevices, err := c.listScsiDevices()
	if err != nil {
		return nil, err
	}
	// only interested in the scsi devices that match the provided LUN
	filteredScsiDevices := filterScsiDevices(scsiDevices, lun)
	if len(filteredScsiDevices) == 0 {
		return nil, errors.New("no matching scsi devices found")
	}
	devices := []snapshot.BlockDevice{}
	for _, device := range filteredScsiDevices {
		log.Debug().Str("device", device.VolumePath).Int("lun", lun).Msg("found device that matches LUN")
		d := snapshot.BlockDevice{
			Name: device.VolumePath,
		}
		devices = append(devices, d)
	}
	return devices, nil
}

func (c *LinuxDeviceManager) identifyViaDeviceName(deviceName string, mountAll bool, includeMounted bool) ([]*snapshot.Partition, error) {
	if deviceName == "" {
		log.Warn().Msg("can't identify partition via device name, no device name provided")
		return []*snapshot.Partition{}, nil
	}

	blockDevices, err := c.cmdRunner.GetBlockDevices()
	if err != nil {
		return nil, err
	}

	device, err := blockDevices.FindDevice(deviceName)
	if err != nil {
		return nil, err
	}

	// Return all non-boot partitions so that tryDetectAsset can iterate
	// through them and find the one containing the OS, which may not be
	// the largest partition (e.g., Bottlerocket's data partition is larger
	// than its root partition). When mountAll is true, boot partitions
	// are included as well.
	return device.GetPartitions(mountAll, includeMounted)
}
