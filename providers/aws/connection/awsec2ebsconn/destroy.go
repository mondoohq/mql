// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsec2ebsconn

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/rs/zerolog/log"
	awsec2ebstypes "go.mondoo.com/mql/providers/aws/connection/awsec2ebsconn/types"
)

func (c *AwsEbsConnection) DetachVolumeFromInstance(ctx context.Context, volume *awsec2ebstypes.VolumeInfo) error {
	if volume == nil {
		return nil // no-op
	}
	log.Info().Msg("detach volume")
	deviceName := c.deviceLocation
	res, err := c.scannerRegionEc2svc.DetachVolume(ctx, &ec2.DetachVolumeInput{
		Device: aws.String(deviceName), VolumeId: &volume.Id,
		InstanceId: &c.scannerInstance.Id,
	})
	if err != nil {
		return err
	}
	if res.State != types.VolumeAttachmentStateDetached { // check if it's detached already
		var volState types.VolumeState
		for volState != types.VolumeStateAvailable {
			time.Sleep(10 * time.Second)
			resp, err := c.scannerRegionEc2svc.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{volume.Id}})
			if err != nil {
				return err
			}
			if len(resp.Volumes) == 1 {
				volState = resp.Volumes[0].State

				log.Info().Interface("state", volState).Msg("waiting for volume detachment completion")
			}
		}
	}
	return nil
}

func (c *AwsEbsConnection) DeleteCreatedVolume(ctx context.Context, volume *awsec2ebstypes.VolumeInfo) error {
	log.Info().Msg("delete created volume")
	_, err := c.scannerRegionEc2svc.DeleteVolume(ctx, &ec2.DeleteVolumeInput{VolumeId: &volume.Id})
	return err
}
