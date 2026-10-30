// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsec2ebsconn

import (
	"context"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	awsec2ebstypes "go.mondoo.com/mql/providers/aws/connection/awsec2ebsconn/types"
	"go.mondoo.com/mql/providers/os/connection/device"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/snapshot"
	"go.mondoo.com/mql/providers/os/id/awsec2"
)

const (
	EBSConnectionType shared.ConnectionType = "ebs"
)

var _ plugin.Closer = (*AwsEbsConnection)(nil)

type AwsEbsConnection struct {
	plugin.Connection
	asset               *inventory.Asset
	DeviceProvider      *device.DeviceConnection
	scannerRegionEc2svc *ec2.Client
	targetRegionEc2svc  *ec2.Client
	config              aws.Config
	opts                map[string]string
	scannerInstance     *awsec2ebstypes.InstanceId // the instance the transport is running on
	scanVolumeInfo      *awsec2ebstypes.VolumeInfo // the info of the volume we attached to the instance
	target              awsec2ebstypes.TargetInfo  // info about the target
	targetType          string                     // the type of object we're targeting (instance, volume, snapshot)
	deviceLocation      string                     // where the device is attached to the instance (e.g. /dev/sda)
}

// New creates a new aws-ec2-ebs provider
// It expects to be running on an ec2 instance with ssm iam role and
// permissions for copy snapshot, create snapshot, create volume, attach volume, detach volume
func NewAwsEbsConnection(id uint32, conf *inventory.Config, asset *inventory.Asset) (*AwsEbsConnection, error) {
	log.Debug().Msg("new aws ebs connection")
	// TODO: validate the expected permissions here
	// TODO: allow custom aws config
	// 1. validate; load
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "could not load aws configuration")
	}
	i, err := RawInstanceInfo(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "could not load instance info: aws-ec2-ebs provider only valid on ec2 instances")
	}

	// ec2 client for the scanner region
	cfg.Region = i.Region
	scannerSvc := ec2.NewFromConfig(cfg)

	targetRegion := conf.Options["region"]
	if targetRegion == "" {
		log.Info().Msg("flag --region not specified, using scanner instance region")
		targetRegion = i.Region
	}

	// ec2 client for the target region
	cfgCopy := cfg.Copy()
	cfgCopy.Region = targetRegion
	targetSvc := ec2.NewFromConfig(cfgCopy)

	// 2. create provider instance
	c := &AwsEbsConnection{
		Connection: plugin.NewConnection(id, asset),
		config:     cfg,
		opts:       conf.Options,
		target: awsec2ebstypes.TargetInfo{
			PlatformId: conf.PlatformId,
			Region:     targetRegion,
			Id:         conf.Options["id"],
		},
		targetType: conf.Options["type"],
		scannerInstance: &awsec2ebstypes.InstanceId{
			Id:      i.InstanceID,
			Region:  i.Region,
			Account: i.AccountID,
			Zone:    i.AvailabilityZone,
		},
		targetRegionEc2svc:  targetSvc,
		scannerRegionEc2svc: scannerSvc,
		asset:               asset,
	}
	log.Debug().Interface("info", c.target).Str("type", c.targetType).Msg("target")

	ctx := context.Background()

	// 3. validate
	instanceinfo, volumeid, snapshotid, err := c.Validate(ctx)
	if err != nil {
		return c, errors.Wrap(err, "unable to validate")
	}

	// 4. setup the volume for scanning
	// check if we got the no setup override option. this implies the target volume is already attached to the instance
	// this is used in cases where we need to test a snapshot created from a public marketplace image. the volume gets attached to a brand
	// new instance, and then that instance is started and we scan the attached fs
	var volLocation string
	if conf.Options[snapshot.NoSetup] == "true" || conf.Options[snapshot.IsSetup] == "true" {
		log.Info().Msg("skipping setup step")
	} else {
		var ok bool
		var err error
		switch c.targetType {
		case awsec2ebstypes.EBSTargetInstance:
			ok, volLocation, _, err = c.SetupForTargetInstance(ctx, instanceinfo)
			conf.PlatformId = awsec2.MondooInstanceID(i.AccountID, targetRegion, convert.ToValue(instanceinfo.InstanceId))
		case awsec2ebstypes.EBSTargetVolume:
			ok, volLocation, _, err = c.SetupForTargetVolume(ctx, *volumeid)
			conf.PlatformId = awsec2.MondooVolumeID(volumeid.Account, volumeid.Region, volumeid.Id)
		case awsec2ebstypes.EBSTargetSnapshot:
			ok, volLocation, _, err = c.SetupForTargetSnapshot(ctx, *snapshotid)
			conf.PlatformId = awsec2.MondooSnapshotID(snapshotid.Account, snapshotid.Region, snapshotid.Id)
		default:
			return c, errors.New("invalid target type")
		}
		if err != nil {
			log.Error().Err(err).Msg("unable to complete setup step")
			c.Close()
			return c, err
		}
		if !ok {
			c.Close()
			return c, errors.New("something went wrong; unable to complete setup for ebs volume scan")
		}
		// set is setup to true
		asset.Connections[0].Options[snapshot.IsSetup] = "true"
		// save the other information to asset connection options too
		if c.scanVolumeInfo.Tags["createdBy"] == "Mondoo" {
			asset.Connections[0].Options["createdBy"] = "Mondoo"
		}
	}

	if conf.Options[snapshot.NoSetup] == "true" {
		conf.PlatformId = awsec2.MondooInstanceID(i.AccountID, targetRegion, convert.ToValue(instanceinfo.InstanceId))
	}
	asset.PlatformIds = []string{conf.PlatformId}
	c.deviceLocation = volLocation

	// this indicates to the device connection which device to mount
	conf.Options["device-name"] = c.deviceLocation
	deviceConn, err := device.NewDeviceConnection(id, &inventory.Config{
		Type:       "device",
		PlatformId: conf.PlatformId,
		Options:    conf.Options,
		Runtime:    "aws-ebs",
	}, asset)
	if err != nil {
		c.Close()
		return nil, err
	}
	c.DeviceProvider = deviceConn
	asset.Id = conf.Type
	asset.Platform.Runtime = c.Runtime()
	return c, nil
}

// no-op since ebs connection doesn't do any verification
func (c *AwsEbsConnection) Hash() uint64            { return 0 }
func (c *AwsEbsConnection) Verify() (string, error) { return "no-op", nil }
func (c *AwsEbsConnection) SetAccountId(_ string)   {}

func (c *AwsEbsConnection) FileInfo(path string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, errors.New("FileInfo not implemented")
}

func (c *AwsEbsConnection) FileSystem() afero.Fs {
	return c.DeviceProvider.FileSystem()
}

func (c *AwsEbsConnection) Close() {
	log.Debug().Msg("close aws ebs connection")
	if c.opts != nil {
		if c.opts[snapshot.NoSetup] == "true" {
			return
		}
	}
	if c.DeviceProvider != nil {
		c.DeviceProvider.Close()
	}

	// close volume: we detach and delete it
	//
	// first, check if we have volume information
	if c.scanVolumeInfo == nil {
		log.Debug().Msg("skipping 'closing' volume, no volume information")
		return
	}

	ctx := context.Background()
	err := c.DetachVolumeFromInstance(ctx, c.scanVolumeInfo)
	if err != nil {
		log.Error().Err(err).Msg("unable to detach volume")
	}

	// only delete the volume if we created it, e.g., if we're scanning a snapshot
	if val, ok := c.scanVolumeInfo.Tags["createdBy"]; ok {
		if val == "Mondoo" {
			err := c.DeleteCreatedVolume(ctx, c.scanVolumeInfo)
			if err != nil {
				log.Error().Err(err).Msg("unable to delete volume")
			}
			log.Info().Str("vol-id", c.scanVolumeInfo.Id).Msg("deleted temporary volume created by Mondoo")
		}
	} else {
		log.Debug().Str("vol-id", c.scanVolumeInfo.Id).Msg("skipping volume deletion, not created by Mondoo")
	}
}

func RawInstanceInfo(cfg aws.Config) (*imds.InstanceIdentityDocument, error) {
	metadata := imds.NewFromConfig(cfg)
	ctx := context.Background()
	doc, err := metadata.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		return nil, err
	}
	return &doc.InstanceIdentityDocument, nil
}

func (c *AwsEbsConnection) Identifier() (string, error) {
	return c.target.PlatformId, nil
}

func GetRawInstanceInfo(profile string) (*imds.InstanceIdentityDocument, error) {
	ctx := context.Background()
	var cfg aws.Config
	var err error
	if profile == "" {
		cfg, err = config.LoadDefaultConfig(ctx)
	} else {
		cfg, err = config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile))
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not load aws configuration")
	}
	i, err := RawInstanceInfo(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "could not load instance info: aws-ec2-ebs provider is only valid on ec2 instances")
	}
	return i, nil
}

func NewInstanceId(account string, region string, id string) (*awsec2ebstypes.InstanceId, error) {
	if region == "" || id == "" || account == "" {
		return nil, errors.New("invalid instance id. account, region and instance id required.")
	}
	return &awsec2ebstypes.InstanceId{Account: account, Region: region, Id: id}, nil
}

func ParseInstanceId(path string) (*awsec2ebstypes.InstanceId, error) {
	if !IsValidInstanceId(path) {
		return nil, errors.New("invalid instance id. expected account/<id>/region/<region-val>/instances/<instance-id>")
	}
	keyValues := strings.Split(path, "/")
	if len(keyValues) != 6 {
		return nil, errors.New("invalid instance id. expected account/<id>/region/<region-val>/instances/<instance-id>")
	}
	return NewInstanceId(keyValues[1], keyValues[3], keyValues[5])
}

var VALID_INSTANCE_ID = regexp.MustCompile(`^account/\d{12}/region\/(us(-gov)?|ap|ca|cn|eu|sa)-(central|(north|south)?(east|west)?)-\d\/instances\/.+$`)

func IsValidInstanceId(path string) bool {
	return VALID_INSTANCE_ID.MatchString(path)
}

func resourceTags(resourceType types.ResourceType, instanceId string) []types.TagSpecification {
	return []types.TagSpecification{
		{
			ResourceType: resourceType,
			Tags: []types.Tag{
				{Key: aws.String("createdBy"), Value: aws.String("Mondoo")},
				{Key: aws.String("Created By"), Value: aws.String("Mondoo")},
				{Key: aws.String("Created From Instance"), Value: aws.String(instanceId)},
			},
		},
	}
}

func ParseEbsTransportUrl(path string) (*awsec2ebstypes.EbsTransportTarget, error) {
	keyValues := strings.Split(path, "/")
	if len(keyValues) != 6 {
		return nil, errors.New("invalid id. expected account/<id>/region/<region-val>/{instance, volume, or snapshot}/<id>")
	}

	var itemType string
	switch keyValues[4] {
	case "volume":
		itemType = awsec2ebstypes.EBSTargetVolume
	case "snapshot":
		itemType = awsec2ebstypes.EBSTargetSnapshot
	default:
		itemType = awsec2ebstypes.EBSTargetInstance
	}

	return &awsec2ebstypes.EbsTransportTarget{Account: keyValues[1], Region: keyValues[3], Id: keyValues[5], Type: itemType}, nil
}

func (c *AwsEbsConnection) Name() string {
	return "aws ebs"
}

func (c *AwsEbsConnection) Asset() *inventory.Asset {
	return c.asset
}

func (p *AwsEbsConnection) UpdateAsset(asset *inventory.Asset) {
	p.asset = asset
}

func (c *AwsEbsConnection) Capabilities() shared.Capabilities {
	return shared.Capability_RunCommand // not true, update to nothing
}

func (c *AwsEbsConnection) RunCommand(command string) (*shared.Command, error) {
	return nil, errors.New("unimplemented")
}

func (c *AwsEbsConnection) Type() shared.ConnectionType {
	return EBSConnectionType
}

func (c *AwsEbsConnection) Runtime() string {
	return "aws-ebs"
}

func (c *AwsEbsConnection) PlatformInfo() *inventory.Platform {
	return &inventory.Platform{
		Name:    "aws-ebs",
		Title:   "aws-ebs",
		Runtime: c.Runtime(),
	}
}
