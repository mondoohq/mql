// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsSecurityhub) softwarePackages() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSoftwarePackages(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

// isSecurityHubV2NotEnabled reports whether a Security Hub (V2) call failed
// because the service is not enabled in the region.
func isSecurityHubV2NotEnabled(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := errors.AsType[*types.ResourceNotFoundException](err); ok {
		return true
	}
	if _, ok := errors.AsType[*types.InvalidAccessException](err); ok {
		return true
	}
	return false
}

func (a *mqlAwsSecurityhub) getSoftwarePackages(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("securityhub>getSoftwarePackages>calling aws with region %s", region)
			svc := conn.Securityhub(region)
			ctx := context.Background()
			res := []any{}

			paginator := securityhub.NewGetSoftwareV2Paginator(svc, &securityhub.GetSoftwareV2Input{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS Security Hub software inventory")
						return res, nil
					}
					if isSecurityHubV2NotEnabled(err) || IsServiceNotAvailableInRegionError(err) {
						return res, nil
					}
					return nil, err
				}
				for _, sw := range page.Software {
					mqlSw, err := newMqlAwsSecurityhubSoftwarePackage(a.MqlRuntime, region, sw)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSw)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// securityhubSoftwarePackageId keys a package by the region it was read from
// and its name, type, and version: GetSoftwareV2 returns one entry per
// combination, and a version-less entry differs from one with a version.
func securityhubSoftwarePackageId(region string, sw types.SoftwareResult) string {
	version := "-"
	if sw.PackageVersion != nil {
		version = "v=" + *sw.PackageVersion
	}
	return fmt.Sprintf("securityhub/software/%s/%s/%s/%s",
		region, convert.ToValue(sw.PackageType), convert.ToValue(sw.PackageName), version)
}

type mqlAwsSecurityhubSoftwarePackageInternal struct {
	cachePackageVersion *string
}

func newMqlAwsSecurityhubSoftwarePackage(runtime *plugin.Runtime, region string, sw types.SoftwareResult) (*mqlAwsSecurityhubSoftwarePackage, error) {
	res, err := CreateResource(runtime, "aws.securityhub.softwarePackage",
		map[string]*llx.RawData{
			"__id":           llx.StringData(securityhubSoftwarePackageId(region, sw)),
			"packageName":    llx.StringDataPtr(sw.PackageName),
			"packageType":    llx.StringDataPtr(sw.PackageType),
			"packageVersion": llx.StringDataPtr(sw.PackageVersion),
			"resourceCount":  llx.IntDataDefault(sw.ResourceCount, 0),
			"region":         llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mqlSw := res.(*mqlAwsSecurityhubSoftwarePackage)
	mqlSw.cachePackageVersion = sw.PackageVersion
	return mqlSw, nil
}

func (a *mqlAwsSecurityhubSoftwarePackage) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsSecurityhubSoftwarePackage) resources() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Securityhub(region)
	ctx := context.Background()

	name := a.PackageName.Data
	pkgType := a.PackageType.Data
	input := &securityhub.GetSoftwareResourcesV2Input{
		PackageName:    &name,
		PackageType:    &pkgType,
		PackageVersion: a.cachePackageVersion,
	}

	res := []any{}
	paginator := securityhub.NewGetSoftwareResourcesV2Paginator(svc, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return nil, llx.Forbidden(err, llx.WithPermissions("securityhub:GetSoftwareResourcesV2"))
			}
			return nil, err
		}
		for _, r := range page.SoftwareResources {
			mqlRes, err := CreateResource(a.MqlRuntime, "aws.securityhub.softwareResource",
				map[string]*llx.RawData{
					"__id": llx.StringData(fmt.Sprintf("securityhub/softwareResource/%s/%s/%s/%s",
						convert.ToValue(r.AccountId), convert.ToValue(r.Region), convert.ToValue(r.ResourceType), convert.ToValue(r.ResourceId))),
					"resourceId":             llx.StringDataPtr(r.ResourceId),
					"resourceType":           llx.StringDataPtr(r.ResourceType),
					"resourceProvider":       llx.StringDataPtr(r.ResourceProvider),
					"resourceRegion":         llx.StringDataPtr(r.ResourceRegion),
					"resourceCloudPartition": llx.StringDataPtr(r.ResourceCloudPartition),
					"resourceOwnerAccountId": llx.StringDataPtr(r.ResourceOwnerAccountId),
					"resourceOwnerOrgId":     llx.StringDataPtr(r.ResourceOwnerOrgId),
					"accountId":              llx.StringDataPtr(r.AccountId),
					"region":                 llx.StringDataPtr(r.Region),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRes)
		}
	}
	return res, nil
}

func (a *mqlAwsSecurityhubSoftwareResource) id() (string, error) {
	return a.__id, nil
}

// securityhubSoftwareResourceArn returns the ARN of an AWS resource from the
// Security Hub inventory when it has the wanted type and belongs to the
// scanned account, and "" otherwise. The resource ID is either an ARN or a
// bare ID (an instance ID or function name), from which the ARN is built.
func securityhubSoftwareResourceArn(r softwareResourceRef, wantType string, scannedAccount string) string {
	if r.resourceType != wantType || r.resourceId == "" {
		return ""
	}
	if strings.HasPrefix(r.resourceId, "arn:") {
		parsed, err := arn.Parse(r.resourceId)
		if err != nil || parsed.AccountID != scannedAccount {
			return ""
		}
		return r.resourceId
	}

	account := r.ownerAccountId
	if account == "" {
		account = r.accountId
	}
	if account != scannedAccount {
		return ""
	}
	region := r.resourceRegion
	if region == "" {
		region = r.region
	}
	partition := r.partition
	if partition == "" {
		partition = "aws"
	}
	switch wantType {
	case "AWS::EC2::Instance":
		return fmt.Sprintf("arn:%s:ec2:%s:%s:instance/%s", partition, region, account, r.resourceId)
	case "AWS::Lambda::Function":
		return fmt.Sprintf("arn:%s:lambda:%s:%s:function:%s", partition, region, account, r.resourceId)
	}
	return ""
}

type softwareResourceRef struct {
	resourceId     string
	resourceType   string
	resourceRegion string
	region         string
	partition      string
	ownerAccountId string
	accountId      string
}

func (a *mqlAwsSecurityhubSoftwareResource) ref() softwareResourceRef {
	return softwareResourceRef{
		resourceId:     a.ResourceId.Data,
		resourceType:   a.ResourceType.Data,
		resourceRegion: a.ResourceRegion.Data,
		region:         a.Region.Data,
		partition:      a.ResourceCloudPartition.Data,
		ownerAccountId: a.ResourceOwnerAccountId.Data,
		accountId:      a.AccountId.Data,
	}
}

func (a *mqlAwsSecurityhubSoftwareResource) ec2Instance() (*mqlAwsEc2Instance, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	instanceArn := securityhubSoftwareResourceArn(a.ref(), "AWS::EC2::Instance", conn.AccountId())
	if instanceArn == "" {
		a.Ec2Instance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.ec2.instance",
		map[string]*llx.RawData{"arn": llx.StringData(instanceArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Instance), nil
}

func (a *mqlAwsSecurityhubSoftwareResource) lambdaFunction() (*mqlAwsLambdaFunction, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	functionArn := securityhubSoftwareResourceArn(a.ref(), "AWS::Lambda::Function", conn.AccountId())
	if functionArn == "" {
		a.LambdaFunction.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.lambda.function",
		map[string]*llx.RawData{"arn": llx.StringData(functionArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsLambdaFunction), nil
}
