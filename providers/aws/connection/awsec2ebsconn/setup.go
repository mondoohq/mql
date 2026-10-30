// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsec2ebsconn

import (
	"context"
	"math/rand"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	awsec2ebstypes "go.mondoo.com/mql/providers/aws/connection/awsec2ebsconn/types"
)

func (c *AwsEbsConnection) Validate(ctx context.Context) (*types.Instance, *awsec2ebstypes.VolumeInfo, *awsec2ebstypes.SnapshotId, error) {
	target := c.target
	switch c.targetType {
	case awsec2ebstypes.EBSTargetInstance:
		log.Info().Interface("instance", target).Msg("validate state")
		resp, err := c.targetRegionEc2svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{target.Id}})
		if err != nil {
			return nil, nil, nil, err
		}
		if !InstanceIsInRunningOrStoppedState(resp.Reservations[0].Instances[0].State) {
			return nil, nil, nil, errors.New("instance must be in running or stopped state")
		}
		return &resp.Reservations[0].Instances[0], nil, nil, nil
	case awsec2ebstypes.EBSTargetVolume:
		log.Info().Interface("volume", target).Msg("validate exists")
		vols, err := c.targetRegionEc2svc.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{target.Id}})
		if err != nil {
			return nil, nil, nil, err
		}
		if len(vols.Volumes) > 0 {
			vol := vols.Volumes[0]
			if vol.State != types.VolumeStateAvailable {
				// we can still scan it, it just means we have to do the whole snapshot/create volume dance
				log.Warn().Msg("volume specified is not in available state")
				return nil, &awsec2ebstypes.VolumeInfo{Id: c.target.Id, Account: c.target.AccountId, Region: c.target.Region, IsAvailable: false, Tags: awsTagsToMap(vol.Tags)}, nil, nil
			}
			return nil, &awsec2ebstypes.VolumeInfo{Id: c.target.Id, Account: c.target.AccountId, Region: c.target.Region, IsAvailable: true, Tags: awsTagsToMap(vol.Tags)}, nil, nil
		}
	case awsec2ebstypes.EBSTargetSnapshot:
		log.Info().Interface("snapshot", target).Msg("validate exists")
		snaps, err := c.targetRegionEc2svc.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{target.Id}})
		if err != nil {
			return nil, nil, nil, err
		}
		if len(snaps.Snapshots) > 0 {
			return nil, nil, &awsec2ebstypes.SnapshotId{Id: c.target.Id, Account: c.target.AccountId, Region: c.target.Region}, nil
		}
	default:
		return nil, nil, nil, errors.New("cannot validate; unrecognized ebs target")
	}
	return nil, nil, nil, errors.New("cannot validate; unrecognized ebs target")
}

func (c *AwsEbsConnection) SetupForTargetVolume(ctx context.Context, volume awsec2ebstypes.VolumeInfo) (bool, string, string, error) {
	log.Debug().Interface("volume", volume).Msg("setup for target volume")
	if !volume.IsAvailable {
		return c.SetupForTargetVolumeUnavailable(ctx, volume)
	}
	c.scanVolumeInfo = &volume
	return c.AttachVolumeToInstance(ctx, volume)
}

func (c *AwsEbsConnection) SetupForTargetVolumeUnavailable(ctx context.Context, volume awsec2ebstypes.VolumeInfo) (bool, string, string, error) {
	found, snapId, err := c.FindRecentSnapshotForVolume(ctx, volume)
	if err != nil {
		// only log the error here, this is not a blocker
		log.Error().Err(err).Msg("unable to find recent snapshot for volume")
	}
	if !found {
		snapId, err = c.CreateSnapshotFromVolume(ctx, volume)
		if err != nil {
			return false, "", "", err
		}
	}
	snapId, err = c.CopySnapshotToRegion(ctx, snapId)
	if err != nil {
		return false, "", "", err
	}
	volId, err := c.CreateVolumeFromSnapshot(ctx, snapId)
	if err != nil {
		return false, "", "", err
	}
	c.scanVolumeInfo = &volId
	return c.AttachVolumeToInstance(ctx, volId)
}

func (c *AwsEbsConnection) SetupForTargetSnapshot(ctx context.Context, snapshot awsec2ebstypes.SnapshotId) (bool, string, string, error) {
	log.Debug().Interface("snapshot", snapshot).Msg("setup for target snapshot")
	snapId, err := c.CopySnapshotToRegion(ctx, snapshot)
	if err != nil {
		return false, "", "", err
	}
	volId, err := c.CreateVolumeFromSnapshot(ctx, snapId)
	if err != nil {
		return false, "", "", err
	}
	c.scanVolumeInfo = &volId
	return c.AttachVolumeToInstance(ctx, volId)
}

func (c *AwsEbsConnection) SetupForTargetInstance(ctx context.Context, instanceinfo *types.Instance) (bool, string, string, error) {
	log.Debug().Str("instance id", *instanceinfo.InstanceId).Msg("setup for target instance")
	var err error
	v, err := c.GetVolumeInfoForInstance(ctx, instanceinfo)
	if err != nil {
		return false, "", "", err
	}
	found, snapId, err := c.FindRecentSnapshotForVolume(ctx, v)
	if err != nil {
		// only log the error here, this is not a blocker
		log.Error().Err(err).Msg("unable to find recent snapshot for volume")
	}
	if !found {
		snapId, err = c.CreateSnapshotFromVolume(ctx, v)
		if err != nil {
			return false, "", "", err
		}
	}
	snapId, err = c.CopySnapshotToRegion(ctx, snapId)
	if err != nil {
		return false, "", "", err
	}
	volId, err := c.CreateVolumeFromSnapshot(ctx, snapId)
	if err != nil {
		return false, "", "", err
	}
	c.scanVolumeInfo = &volId
	return c.AttachVolumeToInstance(ctx, volId)
}

func (c *AwsEbsConnection) GetVolumeInfoForInstance(ctx context.Context, instanceinfo *types.Instance) (awsec2ebstypes.VolumeInfo, error) {
	i := c.target
	log.Info().Interface("instance", i).Msg("find volume id")

	if volID := GetVolumeInfoForInstance(instanceinfo); volID != nil {
		return awsec2ebstypes.VolumeInfo{Id: *volID, Region: i.Region, Account: i.AccountId, Tags: map[string]string{}}, nil
	}
	return awsec2ebstypes.VolumeInfo{}, errors.New("no volume id found for instance")
}

// conventionalRootDeviceNames are the device names AWS gives a root volume on
// the standard AMIs. They are only consulted when the instance does not report
// a RootDeviceName of its own, which should not happen for an EBS-backed
// instance.
var conventionalRootDeviceNames = []string{"/dev/xvda", "/dev/sda1"}

// GetVolumeInfoForInstance returns the EBS volume backing an instance's root
// device, or nil when it cannot be identified.
//
// The instance says which device is the root one, in RootDeviceName, so match
// on that. The device name was previously guessed with a substring test for
// "xvda" or "sda1", which was wrong in both directions: an AMI whose root
// device is neither found nothing, and because "xvda" is a substring of
// "xvda1" a *data* volume at /dev/xvda1 could be picked ahead of the real root
// at /dev/xvda. That second case is the dangerous one - the scan reports the
// wrong filesystem's operating system and packages, and nothing errors.
//
// Returning nil is better than guessing: the caller turns it into "no volume
// id found for instance", which names the problem, where a wrong volume does
// not.
func GetVolumeInfoForInstance(instanceinfo *types.Instance) *string {
	if instanceinfo == nil {
		return nil
	}

	// An instance-store mapping carries no EBS volume, so it is not a
	// candidate and dereferencing it would panic.
	ebsMappings := make([]types.InstanceBlockDeviceMapping, 0, len(instanceinfo.BlockDeviceMappings))
	for i := range instanceinfo.BlockDeviceMappings {
		mapping := instanceinfo.BlockDeviceMappings[i]
		if mapping.Ebs == nil || mapping.Ebs.VolumeId == nil {
			continue
		}
		log.Debug().Str("device", aws.ToString(mapping.DeviceName)).Msg("found instance block device")
		ebsMappings = append(ebsMappings, mapping)
	}
	if len(ebsMappings) == 0 {
		return nil
	}

	if rootDeviceName := aws.ToString(instanceinfo.RootDeviceName); rootDeviceName != "" {
		for i := range ebsMappings {
			if aws.ToString(ebsMappings[i].DeviceName) == rootDeviceName {
				return ebsMappings[i].Ebs.VolumeId
			}
		}
	}

	// Either the instance reported no RootDeviceName, or it named a device
	// that carries no EBS volume. A single EBS volume is unambiguous in
	// both cases.
	if len(ebsMappings) == 1 {
		return ebsMappings[0].Ebs.VolumeId
	}

	for i := range ebsMappings {
		if slices.Contains(conventionalRootDeviceNames, aws.ToString(ebsMappings[i].DeviceName)) {
			return ebsMappings[i].Ebs.VolumeId
		}
	}
	return nil
}

func (c *AwsEbsConnection) FindRecentSnapshotForVolume(ctx context.Context, v awsec2ebstypes.VolumeInfo) (bool, awsec2ebstypes.SnapshotId, error) {
	return FindRecentSnapshotForVolume(ctx, v, c.scannerRegionEc2svc)
}

func FindRecentSnapshotForVolume(ctx context.Context, v awsec2ebstypes.VolumeInfo, svc *ec2.Client) (bool, awsec2ebstypes.SnapshotId, error) {
	log.Info().Msg("find recent snapshot")
	res, err := svc.DescribeSnapshots(ctx,
		&ec2.DescribeSnapshotsInput{Filters: []types.Filter{
			{Name: aws.String("volume-id"), Values: []string{v.Id}},
		}})
	if err != nil {
		return false, awsec2ebstypes.SnapshotId{}, err
	}

	eighthrsago := time.Now().Add(-8 * time.Hour)
	for i := range res.Snapshots {
		// check the start time on all the snapshots
		snapshot := res.Snapshots[i]
		if snapshot.StartTime.After(eighthrsago) {
			s := awsec2ebstypes.SnapshotId{Account: v.Account, Region: v.Region, Id: *snapshot.SnapshotId}
			log.Info().Interface("snapshot", s).Msg("found snapshot")
			snapState := snapshot.State
			timeout := 0
			for snapState != types.SnapshotStateCompleted {
				log.Info().Interface("state", snapState).Msg("waiting for snapshot copy completion; sleeping 10 seconds")
				time.Sleep(10 * time.Second)
				snaps, err := svc.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{s.Id}})
				if err != nil {
					var ae smithy.APIError
					if errors.As(err, &ae) {
						if ae.ErrorCode() == "InvalidSnapshot.NotFound" {
							return false, awsec2ebstypes.SnapshotId{}, nil
						}
					}
					return false, awsec2ebstypes.SnapshotId{}, err
				}
				snapState = snaps.Snapshots[0].State
				if timeout == 6 { // we've waited a minute
					return false, awsec2ebstypes.SnapshotId{}, errors.New("timed out waiting for recent snapshot to complete")
				}
				timeout++
			}
			return true, s, nil
		}
	}
	return false, awsec2ebstypes.SnapshotId{}, nil
}

func (c *AwsEbsConnection) CreateSnapshotFromVolume(ctx context.Context, v awsec2ebstypes.VolumeInfo) (awsec2ebstypes.SnapshotId, error) {
	log.Info().Msg("create snapshot")
	// snapshot the volume
	// use region from volume for aws config
	cfgCopy := c.config.Copy()
	cfgCopy.Region = v.Region
	snapId, err := CreateSnapshotFromVolume(ctx, cfgCopy, v.Id, resourceTags(types.ResourceTypeSnapshot, c.target.Id))
	if err != nil {
		return awsec2ebstypes.SnapshotId{}, err
	}

	return awsec2ebstypes.SnapshotId{Id: *snapId, Region: v.Region, Account: v.Account}, nil
}

func CreateSnapshotFromVolume(ctx context.Context, cfg aws.Config, volID string, tags []types.TagSpecification) (*string, error) {
	ec2svc := ec2.NewFromConfig(cfg)
	res, err := ec2svc.CreateSnapshot(ctx, &ec2.CreateSnapshotInput{VolumeId: &volID, TagSpecifications: tags})
	if err != nil {
		return nil, err
	}

	/*
		NOTE re: encrypted snapshots
		Snapshots that are taken from encrypted volumes are
		automatically encrypted/decrypted. Volumes that are created from encrypted snapshots are
		also automatically encrypted/decrypted.
	*/

	// wait for snapshot to be ready
	time.Sleep(10 * time.Second)
	snapProgress := *res.Progress
	snapState := res.State
	timeout := 0
	notFoundTimeout := 0
	for snapState != types.SnapshotStateCompleted || !strings.Contains(snapProgress, "100") {
		log.Info().Str("progress", snapProgress).Msg("waiting for snapshot completion; sleeping 10 seconds")
		time.Sleep(10 * time.Second)
		snaps, err := ec2svc.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{*res.SnapshotId}})
		if err != nil {
			var ae smithy.APIError
			if errors.As(err, &ae) {
				if ae.ErrorCode() == "InvalidSnapshot.NotFound" {
					time.Sleep(30 * time.Second) // if it says it doesn't exist, even though we just created it, then it must still be busy creating
					notFoundTimeout++
					if notFoundTimeout > 10 {
						return nil, errors.New("timed out waiting for created snapshot to complete; snapshot not found")
					}
					continue
				}
			}
			return nil, err
		}
		if len(snaps.Snapshots) != 1 {
			return nil, errors.Newf("expected one snapshot, got %d", len(snaps.Snapshots))
		}
		snapProgress = *snaps.Snapshots[0].Progress
		snapState = snaps.Snapshots[0].State
		if timeout > 24 { // 4 minutes
			return nil, errors.New("timed out waiting for created snapshot to complete")
		}
	}
	log.Info().Str("progress", snapProgress).Msg("snapshot complete")

	return res.SnapshotId, nil
}

func (c *AwsEbsConnection) CopySnapshotToRegion(ctx context.Context, snapshot awsec2ebstypes.SnapshotId) (awsec2ebstypes.SnapshotId, error) {
	log.Info().Str("snapshot", snapshot.Region).Str("scanner instance", c.scannerInstance.Region).Msg("checking snapshot region")
	if snapshot.Region == c.scannerInstance.Region {
		// we only need to copy the snapshot to the scanner region if it is not already in the same region
		return snapshot, nil
	}
	var newSnapshot awsec2ebstypes.SnapshotId
	log.Info().Msg("copy snapshot")
	// snapshot the volume
	res, err := c.scannerRegionEc2svc.CopySnapshot(ctx, &ec2.CopySnapshotInput{SourceRegion: &snapshot.Region, SourceSnapshotId: &snapshot.Id, TagSpecifications: resourceTags(types.ResourceTypeSnapshot, c.target.Id)})
	if err != nil {
		return newSnapshot, err
	}

	// wait for snapshot to be ready
	snaps, err := c.scannerRegionEc2svc.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{*res.SnapshotId}})
	if err != nil {
		return newSnapshot, err
	}
	snapState := snaps.Snapshots[0].State
	for snapState != types.SnapshotStateCompleted {
		log.Info().Interface("state", snapState).Msg("waiting for snapshot copy completion; sleeping 10 seconds")
		time.Sleep(10 * time.Second)
		snaps, err := c.scannerRegionEc2svc.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{*res.SnapshotId}})
		if err != nil {
			return newSnapshot, err
		}
		snapState = snaps.Snapshots[0].State
	}
	return awsec2ebstypes.SnapshotId{Id: *res.SnapshotId, Region: c.config.Region, Account: c.scannerInstance.Account}, nil
}

func (c *AwsEbsConnection) CreateVolumeFromSnapshot(ctx context.Context, snapshot awsec2ebstypes.SnapshotId) (awsec2ebstypes.VolumeInfo, error) {
	log.Info().Msg("create volume")
	var vol awsec2ebstypes.VolumeInfo

	out, err := c.scannerRegionEc2svc.CreateVolume(ctx, &ec2.CreateVolumeInput{
		SnapshotId:        &snapshot.Id,
		AvailabilityZone:  &c.scannerInstance.Zone,
		TagSpecifications: resourceTags(types.ResourceTypeVolume, c.target.Id),
	})
	if err != nil {
		return vol, err
	}

	/*
		NOTE re: encrypted snapshots
		Snapshots that are taken from encrypted volumes are
		automatically encrypted/decrypted. Volumes that are created from encrypted snapshots are
		also automatically encrypted/decrypted.
	*/

	state := out.State
	for state != types.VolumeStateAvailable {
		log.Info().Interface("state", state).Msg("waiting for volume creation completion; sleeping 10 seconds")
		time.Sleep(10 * time.Second)
		vols, err := c.scannerRegionEc2svc.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{*out.VolumeId}})
		if err != nil {
			return vol, err
		}
		state = vols.Volumes[0].State
	}
	return awsec2ebstypes.VolumeInfo{Id: *out.VolumeId, Region: c.config.Region, Account: c.scannerInstance.Account, Tags: awsTagsToMap(out.Tags)}, nil
}

func newVolumeAttachmentLoc() string {
	chars := []rune("bcdefghijklmnopqrstuvwxyz") // a is reserved for the root volume
	randomIndex := rand.Intn(len(chars))
	c := chars[randomIndex]
	// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/device_naming.html
	return "/dev/sd" + string(c)
}

func AttachVolume(ctx context.Context, ec2svc *ec2.Client, location string, volID string, instanceID string) (string, types.VolumeAttachmentState, error) {
	res, err := ec2svc.AttachVolume(ctx, &ec2.AttachVolumeInput{
		Device: aws.String(location), VolumeId: &volID,
		InstanceId: &instanceID,
	})
	if err != nil {
		log.Error().Err(err).Str("volume", volID).Msg("attach volume err")
		var ae smithy.APIError
		if errors.As(err, &ae) {
			if ae.ErrorCode() != "InvalidParameterValue" {
				// we don't want to return the err if it's invalid parameter value
				return location, "", err
			}
		}
		// if invalid, it could be something else is using that space, try to mount to diff location
		newlocation := newVolumeAttachmentLoc()
		if location != newlocation {
			location = newlocation
		} else {
			location = newVolumeAttachmentLoc() // we shouldn't have gotten the same one the first go round, but it is randomized, so there is a possibility. try again in that case.
		}
		res, err = ec2svc.AttachVolume(ctx, &ec2.AttachVolumeInput{
			Device: aws.String(location), VolumeId: &volID, // warning: there is no guarantee that aws will place the volume at this location
			InstanceId: &instanceID,
		})
		if err != nil {
			log.Error().Err(err).Str("volume", volID).Msg("attach volume err")
			return location, "", err
		}
	}
	if res.Device != nil {
		log.Debug().Str("location", *res.Device).Msg("attached volume")
		location = *res.Device
	}
	return location, res.State, nil
}

func (c *AwsEbsConnection) AttachVolumeToInstance(ctx context.Context, volume awsec2ebstypes.VolumeInfo) (bool, string, string, error) {
	log.Info().Str("volume id", volume.Id).Msg("attach volume")
	ready := false
	loc, state, err := AttachVolume(ctx, c.scannerRegionEc2svc, newVolumeAttachmentLoc(), volume.Id, c.scannerInstance.Id)
	if err != nil {
		return ready, "", "", err
	}
	location := loc // warning: there is no guarantee from AWS that the device will be placed there
	log.Debug().Str("location", location).Msg("target volume")

	/*
		NOTE: re: encrypted volumes
		Encrypted EBS volumes must be attached
		to instances that support Amazon EBS encryption: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html
	*/

	// here we have the attachment state
	if state != types.VolumeAttachmentStateAttached {
		var volState types.VolumeState
		for volState != types.VolumeStateInUse {
			time.Sleep(10 * time.Second)
			resp, err := c.scannerRegionEc2svc.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{volume.Id}})
			if err != nil {
				return ready, location, "", err
			}
			if len(resp.Volumes) == 1 {
				volState = resp.Volumes[0].State
			}
			log.Info().Interface("state", volState).Msg("waiting for volume attachment completion")
		}
	}
	return true, location, volume.Id, nil
}

func awsTagsToMap(tags []types.Tag) map[string]string {
	m := make(map[string]string)
	for _, t := range tags {
		if t.Key != nil && t.Value != nil {
			m[*t.Key] = *t.Value
		}
	}
	return m
}

func InstanceIsInRunningOrStoppedState(state *types.InstanceState) bool {
	// instance state 16 == running, 80 == stopped
	if state == nil {
		return false
	}
	return *state.Code == 16 || *state.Code == 80
}
