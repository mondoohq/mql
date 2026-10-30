// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

// regionSetting pairs an account-level setting value with the region it was read
// from, so a per-region job can report both.
type regionSetting struct {
	region string
	value  string
}

// collectRegionSettings runs read per region and returns the values keyed by
// region. A region the caller cannot read is left out of the map rather than
// reported with an empty value, which would read as a setting that is switched
// off. read takes the region rather than a client so that each caller's
// conn.Ec2 call sits in the same function as its API call, which is what the
// IAM permission extractor traces.
func collectRegionSettings(conn *connection.AwsConnection, read func(region string) (string, error)) (map[string]any, error) {
	regions, err := conn.Regions()
	if err != nil {
		return nil, err
	}

	tasks := make([]*jobpool.Job, 0, len(regions))
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			value, err := read(region)
			if err != nil {
				if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
					return nil, nil
				}
				return nil, err
			}
			return jobpool.JobResult(regionSetting{region: region, value: value}), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}

	poolOfJobs := jobpool.CreatePool(tasks, 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}

	res := map[string]any{}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result == nil {
			continue
		}
		setting := poolOfJobs.Jobs[i].Result.(regionSetting)
		res[setting.region] = setting.value
	}
	return res, nil
}

func (a *mqlAwsEc2) snapshotBlockPublicAccess() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return collectRegionSettings(conn, func(region string) (string, error) {
		svc := conn.Ec2(region)
		resp, err := svc.GetSnapshotBlockPublicAccessState(context.Background(),
			&ec2.GetSnapshotBlockPublicAccessStateInput{})
		if err != nil {
			return "", err
		}
		return string(resp.State), nil
	})
}

func (a *mqlAwsEc2) allowedImagesState() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return collectRegionSettings(conn, func(region string) (string, error) {
		svc := conn.Ec2(region)
		resp, err := svc.GetAllowedImagesSettings(context.Background(),
			&ec2.GetAllowedImagesSettingsInput{})
		if err != nil {
			return "", err
		}
		return convert.ToValue(resp.State), nil
	})
}

// instanceMetadataDefaultsResult carries one region's account-level IMDS
// defaults. AccountLevel is nil for a region with no defaults set.
type instanceMetadataDefaultsResult struct {
	region   string
	defaults *ec2types.InstanceMetadataDefaultsResponse
}

func (a *mqlAwsEc2) instanceMetadataDefaults() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regions, err := conn.Regions()
	if err != nil {
		return nil, err
	}

	tasks := make([]*jobpool.Job, 0, len(regions))
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Ec2(region)
			resp, err := svc.GetInstanceMetadataDefaults(context.Background(),
				&ec2.GetInstanceMetadataDefaultsInput{})
			if err != nil {
				if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
					return nil, nil
				}
				return nil, err
			}
			return jobpool.JobResult(instanceMetadataDefaultsResult{
				region:   region,
				defaults: resp.AccountLevel,
			}), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}

	poolOfJobs := jobpool.CreatePool(tasks, 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}

	res := []any{}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result == nil {
			continue
		}
		result := poolOfJobs.Jobs[i].Result.(instanceMetadataDefaultsResult)
		mqlDefaults, err := CreateResource(a.MqlRuntime, ResourceAwsEc2InstanceMetadataDefault,
			instanceMetadataDefaultArgs(result))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDefaults)
	}
	return res, nil
}

// instanceMetadataDefaultArgs builds the fields of the per-region defaults
// resource. A region with no account-level defaults still gets an entry, with
// every setting null, so that "no default is set" stays distinguishable from a
// default that permits IMDSv1.
func instanceMetadataDefaultArgs(result instanceMetadataDefaultsResult) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":                       llx.StringData("aws.ec2.instanceMetadataDefault/" + result.region),
		"region":                     llx.StringData(result.region),
		"managedByDeclarativePolicy": llx.BoolData(false),
		"httpTokens":                 llx.NilData,
		"httpEndpoint":               llx.NilData,
		"httpPutResponseHopLimit":    llx.NilData,
		"instanceMetadataTags":       llx.NilData,
		"httpTokensEnforced":         llx.NilData,
	}

	defaults := result.defaults
	if defaults == nil {
		return args
	}

	args["httpTokens"] = emptyStringToNil(string(defaults.HttpTokens))
	args["httpEndpoint"] = emptyStringToNil(string(defaults.HttpEndpoint))
	args["instanceMetadataTags"] = emptyStringToNil(string(defaults.InstanceMetadataTags))
	args["httpTokensEnforced"] = emptyStringToNil(string(defaults.HttpTokensEnforced))
	if defaults.HttpPutResponseHopLimit != nil {
		args["httpPutResponseHopLimit"] = llx.IntDataPtr(defaults.HttpPutResponseHopLimit)
	}
	args["managedByDeclarativePolicy"] = llx.BoolData(defaults.ManagedBy == ec2types.ManagedByDeclarativePolicy)

	return args
}

// emptyStringToNil keeps an unset account default null instead of reporting it
// as an empty string, which would compare equal to neither "required" nor
// "optional" but would still look like a value that was read.
func emptyStringToNil(value string) *llx.RawData {
	if value == "" {
		return llx.NilData
	}
	return llx.StringData(value)
}

func (a *mqlAwsEc2) ebsDefaultKmsKeys() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	keyArns, err := collectRegionSettings(conn, func(region string) (string, error) {
		svc := conn.Ec2(region)
		resp, err := svc.GetEbsDefaultKmsKeyId(context.Background(),
			&ec2.GetEbsDefaultKmsKeyIdInput{})
		if err != nil {
			return "", err
		}
		return convert.ToValue(resp.KmsKeyId), nil
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	for region, raw := range keyArns {
		keyArn, ok := raw.(string)
		if !ok || keyArn == "" {
			continue
		}
		mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
			map[string]*llx.RawData{
				"arn":    llx.StringData(keyArn),
				"region": llx.StringData(region),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlKey)
	}
	return res, nil
}

// userData returns the launch script the instance was created with. EC2 keeps it
// in an instance attribute rather than in the describe output, so it costs one
// call per instance and is only fetched when the field is read.
func (a *mqlAwsEc2Instance) userData() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.Region.Data)

	instanceId := a.InstanceId.Data
	attribute, err := svc.DescribeInstanceAttribute(context.Background(),
		&ec2.DescribeInstanceAttributeInput{
			InstanceId: &instanceId,
			Attribute:  ec2types.InstanceAttributeNameUserData,
		})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return "", nil
		}
		return "", err
	}
	if attribute.UserData == nil || attribute.UserData.Value == nil {
		return "", nil
	}

	decoded, err := base64.StdEncoding.DecodeString(*attribute.UserData.Value)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func (a *mqlAwsEc2Instance) userDataPresent() (bool, error) {
	userData := a.GetUserData()
	if userData.Error != nil {
		return false, userData.Error
	}
	return strings.TrimSpace(userData.Data) != "", nil
}
