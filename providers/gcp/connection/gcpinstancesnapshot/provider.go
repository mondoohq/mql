// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gcpinstancesnapshot

import (
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/mrn"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/device"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/snapshot"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/id/gce"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

type scanTarget struct {
	TargetType   string
	ProjectID    string
	Zone         string
	InstanceName string
	SnapshotName string
}

const (
	SnapshotConnectionType shared.ConnectionType = "gcp-snapshot"
)

type scannerInstance struct {
	projectID    string
	zone         string
	instanceName string
}

type mountInfo struct {
	deviceName string
	diskUrl    string
}

func determineScannerInstanceInfo(id uint32, conf *inventory.Config, asset *inventory.Asset) (*scannerInstance, error) {
	// FIXME: need to pass conf
	localConn := local.NewConnection(id, conf, asset)
	pf, detected := detector.DetectOS(localConn)
	if !detected {
		return nil, errors.New("could not detect platform")
	}
	scannerInstanceInfo, err := gce.Resolve(localConn, pf)
	if err != nil {
		return nil, errors.New("GCP snapshot provider must run from a GCP VM instance")
	}
	identity, err := scannerInstanceInfo.Identify()
	if err != nil {
		return nil, errors.New("GCP snapshot provider must run from a GCP VM instance")
	}
	instanceID := identity.PlatformMrn

	// parse the platform id
	// //platformid.api.mondoo.app/runtime/gcp/compute/v1/projects/project-id/zones/us-central1-a/instances/123456789
	platformMrn, err := mrn.NewMRN(instanceID)
	if err != nil {
		return nil, err
	}
	projectID, err := platformMrn.ResourceID("projects")
	if err != nil {
		return nil, err
	}
	zone, err := platformMrn.ResourceID("zones")
	if err != nil {
		return nil, err
	}
	instanceName, err := platformMrn.ResourceID("instances")
	if err != nil {
		return nil, err
	}

	return &scannerInstance{
		projectID:    projectID,
		zone:         zone,
		instanceName: instanceName,
	}, nil
}

func ParseTarget(conf *inventory.Config) scanTarget {
	return scanTarget{
		TargetType:   conf.Options["type"],
		ProjectID:    conf.Options["project-id"],
		Zone:         conf.Options["zone"],
		InstanceName: conf.Options["instance-name"],
		SnapshotName: conf.Options["snapshot-name"],
	}
}

func NewGcpSnapshotConnection(id uint32, conf *inventory.Config, asset *inventory.Asset) (*GcpSnapshotConnection, error) {
	target := ParseTarget(conf)

	// check if we run on a gcp instance
	scanner, err := determineScannerInstanceInfo(id, conf, asset)
	if err != nil {
		return nil, err
	}

	// determine the target
	sc, err := NewSnapshotCreator()
	if err != nil {
		return nil, err
	}

	// setup disk image so and attach it to the instance
	var diskUrl string
	mi := mountInfo{
		deviceName: "cnspec",
	}
	switch target.TargetType {
	case "instance":
		instanceInfo, err := sc.InstanceInfo(target.ProjectID, target.Zone, target.InstanceName)
		if err != nil {
			return nil, err
		}
		if instanceInfo.BootDiskSourceURL == "" {
			return nil, fmt.Errorf("could not find boot disk for instance %s", target.InstanceName)
		}

		if conf.Options["create-snapshot"] != "true" {
			// search for the latest snapshot for this machine
			snapshotUrl, created, err := sc.searchLatestSnapshot(target.ProjectID, instanceInfo.BootDiskSourceURL)
			if status.Code(err) == codes.NotFound {
				// expected behaviour if no snapshot exists, we fall back to cloning the disk
				log.Debug().Msg("no snapshot found, cloning disk from instance")
			} else if err != nil {
				// real error occurred, we abort
				return nil, errors.Wrap(err, "could not search for gcp instance snapshot")
			} else if err == nil && time.Now().Sub(created).Hours() < 8 {
				// use the snapshot if it was created less than 8 hours ago
				log.Debug().Str("snapshot", snapshotUrl).Msg("found latest snapshot")
				diskUrl, err = sc.createSnapshotDisk(snapshotUrl, scanner.projectID, scanner.zone, newDiskName(target.InstanceName))
				if err != nil {
					log.Error().Err(err).Str("disk", diskUrl).Msg("could not complete snapshot disk creation")
					return nil, errors.Wrap(err, "could not create disk from snapshot")
				}
				log.Debug().Str("disk", diskUrl).Msg("created disk from snapshot")
				mi.diskUrl = diskUrl
			} else {
				log.Debug().Msg("no recent snapshot found, cloning disk from instance")
			}
		}

		// if no disk was defined or found, clone the disk attached to the instance
		if mi.diskUrl == "" {
			// clone the disk of the instance to the zone where the scanner runs
			// disk name does not allow colons, therefore we need a custom format
			diskUrl, err = sc.cloneDisk(instanceInfo.BootDiskSourceURL, scanner.projectID, scanner.zone, newDiskName(target.InstanceName))
			if err != nil {
				log.Error().Err(err).Str("disk", diskUrl).Msg("could not complete snapshot creation")
				return nil, errors.Wrap(err, "could not create gcp instance snapshot")
			}
			log.Debug().Str("disk", diskUrl).Msg("cloned disk from instance disk")
			mi.diskUrl = diskUrl

		}
		asset.Name = instanceInfo.InstanceName
		asset.PlatformIds = []string{instanceInfo.PlatformMrn}
	case "snapshot":
		snapshotInfo, err := sc.SnapshotInfo(target.ProjectID, target.SnapshotName)
		if err != nil {
			return nil, err
		}

		diskUrl, err = sc.createSnapshotDisk(snapshotInfo.SnapshotUrl, scanner.projectID, scanner.zone, newDiskName(target.InstanceName))
		if err != nil {
			log.Error().Err(err).Str("disk", diskUrl).Msg("could not complete snapshot disk creation")
			return nil, errors.Wrap(err, "could not create disk from snapshot")
		}
		log.Debug().Str("disk", diskUrl).Msg("created disk from snapshot")
		mi.diskUrl = diskUrl
		asset.Name = conf.Options["snapshot-name"]
		asset.PlatformIds = []string{snapshotInfo.PlatformMrn}
	default:
		return nil, errors.New("invalid target type")
	}

	// attach created disk to the scanner instance
	err = sc.attachDisk(scanner.projectID, scanner.zone, scanner.instanceName, mi.diskUrl, mi.deviceName)
	if err != nil {
		return nil, err
	}
	// this indicates to the device connection which device to mount
	conf.Options["device-name"] = mi.deviceName
	errorHandler := func() {
		// use different err variable to ensure it does not overshadow the real error
		dErr := sc.detachDisk(scanner.projectID, scanner.zone, scanner.instanceName, mi.deviceName)
		if dErr != nil {
			log.Error().Err(dErr).Msg("could not detach created disk")
		}

		dErr = sc.deleteCreatedDisk(mi.diskUrl)
		if dErr != nil {
			log.Error().Err(dErr).Msg("could not delete created disk")
		}
	}

	// create and initialize device conn provider
	deviceConn, err := device.NewDeviceConnection(id, &inventory.Config{
		PlatformId: conf.PlatformId,
		Options:    conf.Options,
		Type:       conf.Type,
		Record:     conf.Record,
	}, asset)
	if err != nil {
		errorHandler()
		return nil, err
	}

	c := &GcpSnapshotConnection{
		DeviceConnection: deviceConn,
		opts:             conf.Options,
		targetType:       target.TargetType,
		snapshotCreator:  sc,
		target:           target,
		scanner:          *scanner,
		mountInfo:        mi,
		identifier:       conf.PlatformId,
	}

	asset.Id = conf.Type
	asset.Platform.Kind = c.Kind()
	asset.Platform.Runtime = c.Runtime()

	return c, nil
}

var _ plugin.Closer = (*GcpSnapshotConnection)(nil)

type GcpSnapshotConnection struct {
	*device.DeviceConnection
	opts map[string]string
	// the type of object we're targeting (instance, disk, snapshot)
	targetType      string
	snapshotCreator *SnapshotCreator
	target          scanTarget
	scanner         scannerInstance
	mountInfo       mountInfo
	identifier      string
}

// no-op
func (c *GcpSnapshotConnection) Hash() uint64 {
	return 0
}

// no-op
func (c *GcpSnapshotConnection) Verify() error {
	return nil
}

func (c *GcpSnapshotConnection) Close() {
	log.Debug().Msg("closing gcp snapshot connection")
	if c == nil {
		return
	}

	if c.opts != nil {
		if c.opts[snapshot.NoSetup] == "true" {
			return
		}
	}

	if c.DeviceConnection != nil {
		c.DeviceConnection.Close()
	}

	if c.snapshotCreator != nil {
		err := c.snapshotCreator.detachDisk(c.scanner.projectID, c.scanner.zone, c.scanner.instanceName, c.mountInfo.deviceName)
		if err != nil {
			log.Error().Err(err).Msg("unable to detach volume")
		}

		err = c.snapshotCreator.deleteCreatedDisk(c.mountInfo.diskUrl)
		if err != nil {
			log.Error().Err(err).Msg("could not delete created disk")
		}
	}
}

func (c *GcpSnapshotConnection) Capabilities() shared.Capabilities {
	// FIXME: this looks strange in a gcp package, but it's C&P from v8
	return shared.Capability_Aws_Ebs
}

func (c *GcpSnapshotConnection) Kind() string {
	return "api"
}

func (c *GcpSnapshotConnection) Runtime() string {
	return "gcp-vm"
}

func (c *GcpSnapshotConnection) Identifier() (string, error) {
	return c.identifier, nil
}

func (c *GcpSnapshotConnection) Type() shared.ConnectionType {
	return SnapshotConnectionType
}

func (c *GcpSnapshotConnection) Config() *inventory.Config {
	return c.DeviceConnection.Conf()
}
