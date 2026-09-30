// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package device

import (
	"errors"
	"runtime"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/device/linux"
	"go.mondoo.com/mql/providers/os/connection/device/windows"
	"go.mondoo.com/mql/providers/os/connection/snapshot"
	"go.mondoo.com/mql/utils/stringx"

	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/id"
	"go.mondoo.com/mql/providers/os/id/ids"
)

const (
	PlatformIdInject   = "inject-platform-ids"
	KeepMounted        = "keep-mounted"
	SkipAssetDetection = "skip-asset-detection"
)

type DeviceConnection struct {
	// represents the single fs where an asset has been identified
	*fs.FileSystemConnection
	plugin.Connection
	asset         *inventory.Asset
	deviceManager DeviceManager

	MountedDirs []string
	// map of mountpoints to partition infos
	partitions map[string]*snapshot.MountedPartition

	// whether to keep the devices mounted after the connection is closed
	keepMounted bool
}

func getDeviceManager(conf *inventory.Config) (DeviceManager, error) {
	shell := []string{"sh", "-c"}
	if runtime.GOOS == "darwin" {
		return nil, errors.New("device manager not implemented for darwin")
	}
	if runtime.GOOS == "windows" {
		shell = []string{"powershell", "-c"}
		return windows.NewWindowsDeviceManager(shell, conf.Options)
	}
	return linux.NewLinuxDeviceManager(shell, conf.Options)
}

func NewDeviceConnection(connId uint32, conf *inventory.Config, asset *inventory.Asset) (*DeviceConnection, error) {
	// allow injecting platform ids into the device connection. we cannot always know the asset that's being scanned, e.g.
	// if we can scan an azure VM's disk we should be able to inject the platform ids of the VM
	if platformIDs, ok := conf.Options[PlatformIdInject]; ok {
		platformIds := strings.Split(platformIDs, ",")
		for _, id := range platformIds {
			if !stringx.Contains(asset.PlatformIds, id) {
				log.Debug().Str("platform-id", id).Msg("device connection> injecting platform id")
				asset.PlatformIds = append(asset.PlatformIds, id)
			}
		}
	}

	manager, err := getDeviceManager(conf)
	if err != nil {
		return nil, err
	}
	log.Debug().Str("manager", manager.Name()).Msg("device manager created")

	partitions, err := manager.IdentifyMountTargets(conf.Options)
	if err != nil {
		log.Warn().Err(err).Msg("device connection> unable to identify some mount targets, proceeding with the rest")
	}

	if len(partitions) == 0 {
		return nil, errors.New("device connection> no partitions found, cannot perform a scan")
	}

	deviceConnection := &DeviceConnection{
		Connection:    plugin.NewConnection(connId, asset),
		deviceManager: manager,
		asset:         asset,
	}

	if conf.Options == nil {
		conf.Options = make(map[string]string)
	}
	deviceConnection.keepMounted = conf.Options[KeepMounted] == "true"

	asset.IdDetector = ids.ExpandDefault(asset.IdDetector, []string{ids.IdDetector_Hostname})
	if !stringx.Contains(asset.IdDetector, ids.IdDetector_MachineID) {
		asset.IdDetector = append(asset.IdDetector, ids.IdDetector_MachineID)
	}
	// This detector helps set the `asset.kind` if the connected device is a cloud instance
	if !stringx.Contains(asset.IdDetector, ids.IdDetector_CloudDetect) {
		asset.IdDetector = append(asset.IdDetector, ids.IdDetector_CloudDetect)
	}

	deviceConnection.partitions = make(map[string]*snapshot.MountedPartition)
	skipAssetDetection := conf.Options[SkipAssetDetection] == "true"

	mountedPartitions, err := manager.Mount(partitions)
	if err != nil {
		log.Warn().Err(err).Msg("device connection> unable to mount some partitions, proceeding with the rest")
	}
	partNames := []string{}
	for _, part := range mountedPartitions {
		deviceConnection.MountedDirs = append(deviceConnection.MountedDirs, part.MountPoint)
		deviceConnection.partitions[part.MountPoint] = part
		partNames = append(partNames, part.Partition.Name)
	}
	if skipAssetDetection {
		log.Debug().Msg("device connection> skipping asset detection as requested")
		return deviceConnection, nil
	}

	log.Debug().
		Strs("partitions", partNames).
		Strs("mountedDirs", deviceConnection.MountedDirs).
		Msg("device connection> mounted partitions, proceeding with asset detection")

	// once everything is mounted, we can try and find the correct partition that holds the OS
	deviceConnection.tryDetectAsset(conf, asset)
	// if none of the blocks returned a platform that we could detect, we return an error
	if asset.Platform == nil {
		log.Debug().Msg("device connection> no platform detected, closing device connection")
		deviceConnection.Close()
		return nil, errors.New("device connection> no platform detected")
	}

	return deviceConnection, nil
}

func (c *DeviceConnection) tryDetectAsset(conf *inventory.Config, asset *inventory.Asset) {
	for mp, partition := range c.partitions {
		log.Debug().Str("mountpoint", mp).Str("path", partition.RootFsPath()).Str("name", partition.Partition.Name).Msg("device connection> trying to detect asset")
		fsConn, err := TryDetectAssetFromPath(c.ID(), partition.RootFsPath(), conf, asset)
		if fsConn != nil {
			c.FileSystemConnection = fsConn
			return
		}
		if err != nil {
			log.Error().Err(err).Str("mountpoint", mp).Str("name", partition.Partition.Name).Msg("partition did not return an asset, continuing")
		}
	}
}

func (c *DeviceConnection) Close() {
	log.Debug().Msg("closing device connection")
	if c == nil {
		return
	}

	if c.deviceManager != nil && !c.keepMounted {
		c.deviceManager.UnmountAndClose()
	}
}

func (p *DeviceConnection) Name() string {
	return "device"
}

func (p *DeviceConnection) Type() shared.ConnectionType {
	return shared.Type_Device
}

func (p *DeviceConnection) Asset() *inventory.Asset {
	return p.asset
}

func (p *DeviceConnection) UpdateAsset(asset *inventory.Asset) {
	p.asset = asset
}

func (p *DeviceConnection) Capabilities() shared.Capabilities {
	return p.FileSystemConnection.Capabilities()
}

func (p *DeviceConnection) RunCommand(command string) (*shared.Command, error) {
	return nil, plugin.ErrRunCommandNotImplemented
}

func (p *DeviceConnection) FileSystem() afero.Fs {
	return p.FileSystemConnection.FileSystem()
}

func (p *DeviceConnection) FileInfo(path string) (shared.FileInfoDetails, error) {
	return p.FileSystemConnection.FileInfo(path)
}

func (p *DeviceConnection) Conf() *inventory.Config {
	return p.FileSystemConnection.Conf
}

func (p *DeviceConnection) Partitions() map[string]*snapshot.MountedPartition {
	if p.partitions == nil {
		p.partitions = make(map[string]*snapshot.MountedPartition)
	}

	return p.partitions
}

// TryDetectAssetFromPath tries to detect the OS on a given path and returns the connection itself if an asset was detected
func TryDetectAssetFromPath(connId uint32, path string, conf *inventory.Config, asset *inventory.Asset) (*fs.FileSystemConnection, error) {
	// create and initialize fs provider
	conf.Options["path"] = path
	fsConn, err := fs.NewConnection(connId, &inventory.Config{
		Path:       path,
		PlatformId: conf.PlatformId,
		Options:    conf.Options,
		Type:       "fs",
		Record:     conf.Record,
	}, asset)
	if err != nil {
		return nil, err
	}

	err = TryDetectAsset(fsConn, path, conf, asset)
	if err != nil {
		return nil, err
	}

	return fsConn, nil
}

func TryDetectAsset(conn shared.Connection, path string, conf *inventory.Config, asset *inventory.Asset) error {
	p, ok := detector.DetectOS(conn)
	if !ok {
		log.Debug().
			Str("path", path).
			Msg("device connection> cannot detect os")
		return errors.New("cannot detect os")
	}

	log.Debug().Str("path", path).Msg("device connection> detected os from path")
	fingerprint, p, err := id.IdentifyPlatform(conn, &plugin.ConnectReq{}, p, asset.IdDetector)
	if err != nil {
		if len(asset.PlatformIds) == 0 {
			log.Debug().Str("path", path).Err(err).Msg("device connection> failed to identify platform from path")
			return err
		}
		log.Warn().Err(err).Msg("device connection> cannot detect platform ids, using existing ones")
	}

	if p == nil {
		log.Debug().Str("path", path).Msg("device connection> no platform detected")
		return errors.New("device connection> no platform detected")
	}

	// even if we get a platform, sometimes its an empty one (e.g. name's empty or unknown)
	if slices.Contains([]string{"", "unknown"}, p.Name) {
		log.Debug().Str("path", path).Msg("device connection> platform name is empty, discarding it")
		return errors.New("device connection> platform found, but empty")
	}

	if asset.Name == "" && fingerprint != nil {
		asset.Name = fingerprint.Name
	}

	if fingerprint != nil {
		asset.PlatformIds = append(asset.PlatformIds, fingerprint.PlatformIDs...)
		asset.IdDetector = fingerprint.ActiveIdDetectors
	}

	asset.Id = conf.Type

	if asset.Platform == nil {
		asset.Platform = p
		log.Debug().Str("path", path).Msg("device connection> using platform os from mountpoint")
	}

	return nil
}
