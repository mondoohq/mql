// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	astypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

type mqlAwsEc2LaunchconfigurationInternal struct {
	cacheImageId string
	securityGroupIdHandler
	region    string
	accountID string
}

func (a *mqlAwsEc2Launchconfiguration) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEc2Launchconfiguration) image() (*mqlAwsEc2Image, error) {
	imageID := a.cacheImageId
	if imageID == "" {
		a.Image.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2Image,
		map[string]*llx.RawData{
			"id":     llx.StringData(imageID),
			"region": llx.StringData(a.Region.Data),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Image), nil
}

func (a *mqlAwsEc2LaunchconfigurationBlockDeviceMapping) id() (string, error) {
	return a.DeviceName.Data, nil
}

func (a *mqlAwsEc2LaunchconfigurationEbsBlockDevice) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEc2LaunchconfigurationEbsBlockDevice) snapshot() (*mqlAwsEc2Snapshot, error) {
	snapshotId := a.cacheSnapshotId
	if snapshotId == "" {
		a.Snapshot.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.ec2.snapshot",
		map[string]*llx.RawData{"id": llx.StringData(snapshotId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Snapshot), nil
}

func (a *mqlAwsEc2LaunchconfigurationMetadataOptions) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEc2Launchconfiguration) securityGroups() ([]any, error) {
	return a.securityGroupIdHandler.newSecurityGroupResources(a.MqlRuntime)
}

func initAwsEc2Launchconfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["name"] == nil || args["region"] == nil {
		return nil, nil, errors.New("name and region required to fetch launch configuration")
	}
	nameVal := args["name"].Value.(string)
	regionVal := args["region"].Value.(string)

	obj, err := CreateResource(runtime, "aws.ec2", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	ec2Res := obj.(*mqlAwsEc2)
	rawResources := ec2Res.GetLaunchConfigurations()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}
	for _, raw := range rawResources.Data {
		lc := raw.(*mqlAwsEc2Launchconfiguration)
		if lc.Name.Data == nameVal && lc.Region.Data == regionVal {
			return args, lc, nil
		}
	}
	return nil, nil, fmt.Errorf("launch configuration %q not found in region %s", nameVal, regionVal)
}

func (a *mqlAwsEc2) launchConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getLaunchConfigurations(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsEc2) getLaunchConfigurations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)

	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		regionVal := region
		f := func() (jobpool.JobResult, error) {
			svc := conn.Autoscaling(regionVal)
			ctx := context.Background()
			res := []any{}

			paginator := autoscaling.NewDescribeLaunchConfigurationsPaginator(svc, &autoscaling.DescribeLaunchConfigurationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", regionVal).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, lc := range page.LaunchConfigurations {
					mqlLc, err := createLaunchConfigurationResource(a.MqlRuntime, conn, lc, regionVal)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlLc)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func createLaunchConfigurationResource(runtime *plugin.Runtime, conn *connection.AwsConnection, lc astypes.LaunchConfiguration, region string) (*mqlAwsEc2Launchconfiguration, error) {
	lcArn := convert.ToValue(lc.LaunchConfigurationARN)

	// Build block device mappings
	bdms, err := createLaunchConfigBlockDeviceMappings(runtime, lcArn, lc.BlockDeviceMappings)
	if err != nil {
		return nil, err
	}

	// Build metadata options
	var metadataArgs map[string]*llx.RawData
	if lc.MetadataOptions != nil {
		metadataArgs = map[string]*llx.RawData{
			"__id":                    llx.StringData(lcArn + "/metadata-options"),
			"httpTokens":              llx.StringData(string(lc.MetadataOptions.HttpTokens)),
			"httpEndpoint":            llx.StringData(string(lc.MetadataOptions.HttpEndpoint)),
			"httpPutResponseHopLimit": llx.IntDataDefault(lc.MetadataOptions.HttpPutResponseHopLimit, 1),
		}
	}

	// Detailed monitoring
	detailedMonitoring := false
	if lc.InstanceMonitoring != nil && lc.InstanceMonitoring.Enabled != nil {
		detailedMonitoring = *lc.InstanceMonitoring.Enabled
	}

	args := map[string]*llx.RawData{
		"arn":                       llx.StringData(lcArn),
		"name":                      llx.StringDataPtr(lc.LaunchConfigurationName),
		"region":                    llx.StringData(region),
		"instanceType":              llx.StringDataPtr(lc.InstanceType),
		"keyName":                   llx.StringDataPtr(lc.KeyName),
		"associatePublicIpAddress":  llx.BoolDataPtr(lc.AssociatePublicIpAddress),
		"ebsOptimized":              llx.BoolDataPtr(lc.EbsOptimized),
		"blockDeviceMappings":       llx.ArrayData(bdms, types.Resource(ResourceAwsEc2LaunchconfigurationBlockDeviceMapping)),
		"detailedMonitoringEnabled": llx.BoolData(detailedMonitoring),
		"iamInstanceProfile":        llx.StringDataPtr(lc.IamInstanceProfile),
		"spotPrice":                 llx.StringDataPtr(lc.SpotPrice),
		"placementTenancy":          llx.StringDataPtr(lc.PlacementTenancy),
		"createdAt":                 llx.TimeDataPtr(lc.CreatedTime),
	}

	// Handle metadata options
	if metadataArgs != nil {
		mqlMeta, err := CreateResource(runtime, ResourceAwsEc2LaunchconfigurationMetadataOptions, metadataArgs)
		if err != nil {
			return nil, err
		}
		args["metadataOptions"] = llx.ResourceData(mqlMeta, mqlMeta.MqlName())
	} else {
		args["metadataOptions"] = llx.NilData
	}

	resource, err := CreateResource(runtime, ResourceAwsEc2Launchconfiguration, args)
	if err != nil {
		return nil, err
	}
	resource.(*mqlAwsEc2Launchconfiguration).cacheImageId = convert.ToValue(lc.ImageId)

	mqlLc := resource.(*mqlAwsEc2Launchconfiguration)
	mqlLc.region = region
	mqlLc.accountID = conn.AccountId()

	// Build security group ARNs
	sgArns := make([]string, len(lc.SecurityGroups))
	for i, sgId := range lc.SecurityGroups {
		sgArns[i] = fmt.Sprintf(securityGroupArnPattern, region, conn.AccountId(), sgId)
	}
	mqlLc.securityGroupIdHandler.setSecurityGroupArns(sgArns)

	return mqlLc, nil
}

func createLaunchConfigBlockDeviceMappings(runtime *plugin.Runtime, lcArn string, mappings []astypes.BlockDeviceMapping) ([]any, error) {
	result := make([]any, 0, len(mappings))
	for _, mapping := range mappings {
		deviceName := convert.ToValue(mapping.DeviceName)
		mappingID := fmt.Sprintf("%s/device/%s", lcArn, deviceName)

		args := map[string]*llx.RawData{
			"__id":        llx.StringData(mappingID),
			"deviceName":  llx.StringDataPtr(mapping.DeviceName),
			"virtualName": llx.StringDataPtr(mapping.VirtualName),
			"noDevice":    llx.BoolDataPtr(mapping.NoDevice),
		}

		if mapping.Ebs != nil {
			ebsID := fmt.Sprintf("%s/ebs", mappingID)
			mqlEbs, err := CreateResource(runtime, ResourceAwsEc2LaunchconfigurationEbsBlockDevice,
				map[string]*llx.RawData{
					"__id":                llx.StringData(ebsID),
					"encrypted":           llx.BoolDataPtr(mapping.Ebs.Encrypted),
					"volumeSize":          llx.IntDataDefault(mapping.Ebs.VolumeSize, 0),
					"volumeType":          llx.StringDataPtr(mapping.Ebs.VolumeType),
					"iops":                llx.IntDataDefault(mapping.Ebs.Iops, 0),
					"throughput":          llx.IntDataDefault(mapping.Ebs.Throughput, 0),
					"deleteOnTermination": llx.BoolDataPtr(mapping.Ebs.DeleteOnTermination),
				})
			if err != nil {
				return nil, err
			}
			mqlEbs.(*mqlAwsEc2LaunchconfigurationEbsBlockDevice).cacheSnapshotId = convert.ToValue(mapping.Ebs.SnapshotId)
			args["ebs"] = llx.ResourceData(mqlEbs, mqlEbs.MqlName())
		} else {
			args["ebs"] = llx.NilData
		}

		mqlMapping, err := CreateResource(runtime, ResourceAwsEc2LaunchconfigurationBlockDeviceMapping, args)
		if err != nil {
			return nil, err
		}
		result = append(result, mqlMapping)
	}
	return result, nil
}

type mqlAwsEc2LaunchconfigurationEbsBlockDeviceInternal struct {
	cacheSnapshotId string
}
