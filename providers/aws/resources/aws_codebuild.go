// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	cbtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

const logGroupArnPattern = "arn:aws:logs:%s:%s:log-group:%s:*"

func (a *mqlAwsCodebuild) id() (string, error) {
	return "aws.codebuild", nil
}

func (a *mqlAwsCodebuild) projects() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getProjects(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsCodebuild) getProjects(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Codebuild(region)
			ctx := context.Background()

			res := []any{}
			names := []string{}
			paginator := codebuild.NewListProjectsPaginator(svc, &codebuild.ListProjectsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				names = append(names, page.Projects...)
			}

			// BatchGetProjects accepts up to 100 names per call.
			for start := 0; start < len(names); start += 100 {
				end := start + 100
				if end > len(names) {
					end = len(names)
				}
				batch, err := svc.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: names[start:end]})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for i := range batch.Projects {
					mqlProject, err := newMqlAwsCodebuildProject(a.MqlRuntime, conn, region, batch.Projects[i])
					if err != nil {
						return nil, err
					}
					res = append(res, mqlProject)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsCodebuildProject) id() (string, error) {
	return a.Name.Data, nil
}

func initAwsCodebuildProject(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// During a discovered-asset scan the resource is queried with no args; recover
	// the project's region and name from the ARN carried on the asset.
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformCodebuildProject); assetArn != "" {
			parsed, err := arn.Parse(assetArn)
			if err != nil {
				return nil, nil, err
			}
			args["region"] = llx.StringData(parsed.Region)
			args["name"] = llx.StringData(strings.TrimPrefix(parsed.Resource, "project/"))
		}
	}

	if args["name"] == nil || args["region"] == nil {
		return nil, nil, errors.New("name and region required to fetch codebuild project")
	}

	// This resource keys its __id on the name alone, so that is the probe key.
	if cached := cachedArg(runtime, ResourceAwsCodebuildProject, args, "name"); cached != nil {
		return args, cached, nil
	}

	name := args["name"].Value.(string)
	region := args["region"].Value.(string)
	conn := runtime.Connection.(*connection.AwsConnection)

	svc := conn.Codebuild(region)
	ctx := context.Background()
	projectDetails, err := svc.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: []string{name}})
	if err != nil {
		return nil, nil, err
	}
	if len(projectDetails.Projects) == 0 {
		return nil, nil, errors.New("aws codebuild project not found")
	}

	mqlProject, err := newMqlAwsCodebuildProject(runtime, conn, region, projectDetails.Projects[0])
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlProject, nil
}

// newMqlAwsCodebuildProject builds a fully populated aws.codebuild.project
// MQL resource from a single CodeBuild API project. Used by both the
// `projects()` iterator and the resource init function so iterated rows have
// every scalar field set without depending on init re-running on field access.
func newMqlAwsCodebuildProject(runtime *plugin.Runtime, conn *connection.AwsConnection, region string, project cbtypes.Project) (plugin.Resource, error) {
	jsonEnv, err := convert.JsonToDict(project.Environment)
	if err != nil {
		return nil, err
	}
	jsonSource, err := convert.JsonToDict(project.Source)
	if err != nil {
		return nil, err
	}
	args := map[string]*llx.RawData{
		// Keyed on the ARN, not the project name: CodeBuild project names are
		// unique per region, so a project deployed to several regions would
		// otherwise alias -- and because the creator writes cacheVpcId /
		// cacheSubnetIds / region onto the returned (cached) resource, the first
		// region's row would then report the second region's network config.
		// aws.codebuild.project is also a discovery asset type, so the aliased
		// project never becomes an asset at all.
		"__id":   llx.StringDataPtr(project.Arn),
		"name":   llx.StringDataPtr(project.Name),
		"region": llx.StringData(region),
	}
	args["arn"] = llx.StringDataPtr(project.Arn)
	args["description"] = llx.StringDataPtr(project.Description)
	args["environment"] = llx.MapData(jsonEnv, types.String)
	args["source"] = llx.MapData(jsonSource, types.String)
	args["tags"] = llx.MapData(cbTagsToMap(project.Tags), types.String)
	args["createdAt"] = llx.TimeDataPtr(project.Created)
	args["modifiedAt"] = llx.TimeDataPtr(project.LastModified)
	args["projectVisibility"] = llx.StringData(string(project.ProjectVisibility))
	args["timeoutInMinutes"] = llx.IntDataDefault(project.TimeoutInMinutes, 60)
	if project.Environment != nil && project.Environment.PrivilegedMode != nil {
		args["privilegedMode"] = llx.BoolData(*project.Environment.PrivilegedMode)
	} else {
		args["privilegedMode"] = llx.BoolData(false)
	}
	args["serviceRole"] = llx.StringDataPtr(project.ServiceRole)
	args["sourceVersion"] = llx.StringDataPtr(project.SourceVersion)
	args["queuedTimeoutInMinutes"] = llx.IntDataDefault(project.QueuedTimeoutInMinutes, 480)

	if project.ConcurrentBuildLimit != nil {
		args["concurrentBuildLimit"] = llx.IntData(int64(*project.ConcurrentBuildLimit))
	} else {
		args["concurrentBuildLimit"] = llx.IntData(0)
	}

	// Artifacts
	primaryArtifacts := project.Artifacts
	args["artifactsType"] = llx.StringData(artifactsTypeString(primaryArtifacts))
	args["artifactsLocation"] = llx.StringData(artifactsField(primaryArtifacts, func(a *cbtypes.ProjectArtifacts) *string { return a.Location }))
	args["artifactsName"] = llx.StringData(artifactsField(primaryArtifacts, func(a *cbtypes.ProjectArtifacts) *string { return a.Name }))
	args["artifactsNamespaceType"] = llx.StringData(artifactsNamespaceString(primaryArtifacts))
	args["artifactsPackaging"] = llx.StringData(artifactsPackagingString(primaryArtifacts))
	args["artifactsPath"] = llx.StringData(artifactsField(primaryArtifacts, func(a *cbtypes.ProjectArtifacts) *string { return a.Path }))
	args["artifactsOverrideArtifactName"] = llx.BoolData(artifactsBoolField(primaryArtifacts, func(a *cbtypes.ProjectArtifacts) *bool { return a.OverrideArtifactName }))
	args["artifactsEncryptionDisabled"] = llx.BoolData(artifactsBoolField(primaryArtifacts, func(a *cbtypes.ProjectArtifacts) *bool { return a.EncryptionDisabled }))
	args["artifactsIdentifier"] = llx.StringData(artifactsField(primaryArtifacts, func(a *cbtypes.ProjectArtifacts) *string { return a.ArtifactIdentifier }))
	args["artifactsBucketOwnerAccess"] = llx.StringData(artifactsBucketOwnerAccessString(primaryArtifacts))

	secondaryArtifacts, err := cbArtifactsToDicts(project.SecondaryArtifacts)
	if err != nil {
		return nil, err
	}
	args["secondaryArtifacts"] = llx.ArrayData(secondaryArtifacts, types.Dict)

	// Cache
	if project.Cache != nil {
		args["cacheType"] = llx.StringData(string(project.Cache.Type))
		args["cacheLocation"] = llx.StringDataPtr(project.Cache.Location)
		modes := make([]any, 0, len(project.Cache.Modes))
		for _, m := range project.Cache.Modes {
			modes = append(modes, string(m))
		}
		args["cacheModes"] = llx.ArrayData(modes, types.String)
	} else {
		args["cacheType"] = llx.StringData("")
		args["cacheLocation"] = llx.StringData("")
		args["cacheModes"] = llx.ArrayData([]any{}, types.String)
	}

	// Logs
	var logsCWEnabled, logsS3Enabled, logsS3EncryptionDisabled bool
	var logsCWGroupName, logsCWStreamName, logsS3Location string
	var cacheLogGroupArn *string
	if project.LogsConfig != nil {
		if cw := project.LogsConfig.CloudWatchLogs; cw != nil {
			logsCWEnabled = cw.Status == cbtypes.LogsConfigStatusTypeEnabled
			if cw.GroupName != nil {
				logsCWGroupName = *cw.GroupName
				if logsCWEnabled && logsCWGroupName != "" {
					arn := fmt.Sprintf(logGroupArnPattern, region, conn.AccountId(), logsCWGroupName)
					cacheLogGroupArn = &arn
				}
			}
			if cw.StreamName != nil {
				logsCWStreamName = *cw.StreamName
			}
		}
		if s3 := project.LogsConfig.S3Logs; s3 != nil {
			logsS3Enabled = s3.Status == cbtypes.LogsConfigStatusTypeEnabled
			if s3.Location != nil {
				logsS3Location = *s3.Location
			}
			if s3.EncryptionDisabled != nil {
				logsS3EncryptionDisabled = *s3.EncryptionDisabled
			}
		}
	}
	args["logsCloudWatchEnabled"] = llx.BoolData(logsCWEnabled)
	args["logsCloudWatchGroupName"] = llx.StringData(logsCWGroupName)
	args["logsCloudWatchStreamName"] = llx.StringData(logsCWStreamName)
	args["logsS3Enabled"] = llx.BoolData(logsS3Enabled)
	args["logsS3Location"] = llx.StringData(logsS3Location)
	args["logsS3EncryptionDisabled"] = llx.BoolData(logsS3EncryptionDisabled)

	// VPC config
	var vpcId string
	var subnetIds, sgIds []string
	var cacheVpcId *string
	if project.VpcConfig != nil {
		if project.VpcConfig.VpcId != nil {
			vpcId = *project.VpcConfig.VpcId
			cacheVpcId = project.VpcConfig.VpcId
		}
		subnetIds = project.VpcConfig.Subnets
		sgIds = project.VpcConfig.SecurityGroupIds
	}
	args["vpcConfigVpcId"] = llx.StringData(vpcId)
	args["vpcConfigSubnetIds"] = llx.ArrayData(stringsToInterface(subnetIds), types.String)
	args["vpcConfigSecurityGroupIds"] = llx.ArrayData(stringsToInterface(sgIds), types.String)

	// Environment scalars + variables
	var (
		envType, envImage, envCompute, envCert, envImagePullCreds string
		envVars                                                   []any
		envComputeVCpu, envComputeMemory, envComputeDisk          int64
		envComputeMachineType, envComputeInstanceType             string
	)
	if project.Environment != nil {
		envType = string(project.Environment.Type)
		if project.Environment.Image != nil {
			envImage = *project.Environment.Image
		}
		envCompute = string(project.Environment.ComputeType)
		if project.Environment.Certificate != nil {
			envCert = *project.Environment.Certificate
		}
		envImagePullCreds = string(project.Environment.ImagePullCredentialsType)
		for _, ev := range project.Environment.EnvironmentVariables {
			evDict := map[string]any{
				"name":  convert.ToValue(ev.Name),
				"value": convert.ToValue(ev.Value),
				"type":  string(ev.Type),
			}
			envVars = append(envVars, evDict)
		}
		if cc := project.Environment.ComputeConfiguration; cc != nil {
			envComputeVCpu = convert.ToValue(cc.VCpu)
			envComputeMemory = convert.ToValue(cc.Memory)
			envComputeDisk = convert.ToValue(cc.Disk)
			envComputeMachineType = string(cc.MachineType)
			envComputeInstanceType = convert.ToValue(cc.InstanceType)
		}
	}
	args["environmentType"] = llx.StringData(envType)
	args["environmentImage"] = llx.StringData(envImage)
	args["environmentComputeType"] = llx.StringData(envCompute)
	args["environmentCertificate"] = llx.StringData(envCert)
	args["environmentImagePullCredentialsType"] = llx.StringData(envImagePullCreds)
	args["environmentVariables"] = llx.ArrayData(envVars, types.Dict)
	args["environmentComputeVCpu"] = llx.IntData(envComputeVCpu)
	args["environmentComputeMemory"] = llx.IntData(envComputeMemory)
	args["environmentComputeDisk"] = llx.IntData(envComputeDisk)
	args["environmentComputeMachineType"] = llx.StringData(envComputeMachineType)
	args["environmentComputeInstanceType"] = llx.StringData(envComputeInstanceType)

	// Source scalars
	var (
		sourceType, sourceLocation, sourceBuildspec, sourceIdentifier string
		sourceGitCloneDepth                                           int64
		sourceInsecureSsl, sourceReportBuildStatus                    bool
	)
	if project.Source != nil {
		sourceType = string(project.Source.Type)
		if project.Source.Location != nil {
			sourceLocation = *project.Source.Location
		}
		if project.Source.GitCloneDepth != nil {
			sourceGitCloneDepth = int64(*project.Source.GitCloneDepth)
		}
		if project.Source.Buildspec != nil {
			sourceBuildspec = *project.Source.Buildspec
		}
		if project.Source.InsecureSsl != nil {
			sourceInsecureSsl = *project.Source.InsecureSsl
		}
		if project.Source.ReportBuildStatus != nil {
			sourceReportBuildStatus = *project.Source.ReportBuildStatus
		}
		if project.Source.SourceIdentifier != nil {
			sourceIdentifier = *project.Source.SourceIdentifier
		}
	}
	args["sourceType"] = llx.StringData(sourceType)
	args["sourceLocation"] = llx.StringData(sourceLocation)
	args["sourceGitCloneDepth"] = llx.IntData(sourceGitCloneDepth)
	args["sourceBuildspec"] = llx.StringData(sourceBuildspec)
	args["sourceInsecureSsl"] = llx.BoolData(sourceInsecureSsl)
	args["sourceReportBuildStatus"] = llx.BoolData(sourceReportBuildStatus)
	args["sourceIdentifier"] = llx.StringData(sourceIdentifier)

	secondarySources := make([]any, 0, len(project.SecondarySources))
	for i := range project.SecondarySources {
		d, err := convert.JsonToDict(project.SecondarySources[i])
		if err != nil {
			return nil, err
		}
		secondarySources = append(secondarySources, d)
	}
	args["secondarySources"] = llx.ArrayData(secondarySources, types.Dict)

	webhookDict, err := convert.JsonToDict(project.Webhook)
	if err != nil {
		return nil, err
	}
	args["webhook"] = llx.MapData(webhookDict, types.String)

	buildBatchDict, err := convert.JsonToDict(project.BuildBatchConfig)
	if err != nil {
		return nil, err
	}
	args["buildBatchConfig"] = llx.MapData(buildBatchDict, types.String)

	args["autoRetryLimit"] = llx.IntDataDefault(project.AutoRetryLimit, 0)
	args["publicProjectAlias"] = llx.StringDataPtr(project.PublicProjectAlias)

	badgeEnabled := false
	badgeRequestURL := ""
	if project.Badge != nil {
		badgeEnabled = project.Badge.BadgeEnabled
		badgeRequestURL = convert.ToValue(project.Badge.BadgeRequestUrl)
	}
	args["badgeEnabled"] = llx.BoolData(badgeEnabled)
	args["badgeRequestUrl"] = llx.StringData(badgeRequestURL)

	fsLocations := make([]any, 0, len(project.FileSystemLocations))
	for _, fs := range project.FileSystemLocations {
		fsLocations = append(fsLocations, map[string]any{
			"type":         string(fs.Type),
			"identifier":   convert.ToValue(fs.Identifier),
			"location":     convert.ToValue(fs.Location),
			"mountPoint":   convert.ToValue(fs.MountPoint),
			"mountOptions": convert.ToValue(fs.MountOptions),
		})
	}
	args["fileSystemLocations"] = llx.ArrayData(fsLocations, types.Dict)

	secSrcVersions := make([]any, 0, len(project.SecondarySourceVersions))
	for _, sv := range project.SecondarySourceVersions {
		secSrcVersions = append(secSrcVersions, map[string]any{
			"sourceIdentifier": convert.ToValue(sv.SourceIdentifier),
			"sourceVersion":    convert.ToValue(sv.SourceVersion),
		})
	}
	args["secondarySourceVersions"] = llx.ArrayData(secSrcVersions, types.Dict)

	obj, err := CreateResource(runtime, "aws.codebuild.project", args)
	if err != nil {
		return nil, err
	}
	mqlProject := obj.(*mqlAwsCodebuildProject)
	mqlProject.cacheEncryptionKeyArn = project.EncryptionKey
	mqlProject.cacheServiceRoleArn = project.ServiceRole
	mqlProject.cacheResourceAccessRoleArn = project.ResourceAccessRole
	mqlProject.cacheLogGroupArn = cacheLogGroupArn
	mqlProject.cacheVpcId = cacheVpcId
	mqlProject.cacheSubnetIds = subnetIds
	mqlProject.region = region
	mqlProject.accountID = conn.AccountId()
	// Pre-compute security group ARNs for the embedded handler
	sgArns := make([]string, 0, len(sgIds))
	for _, sgId := range sgIds {
		sgArns = append(sgArns, NewSecurityGroupArn(region, conn.AccountId(), sgId))
	}
	mqlProject.setSecurityGroupArns(sgArns)
	return mqlProject, nil
}

type mqlAwsCodebuildProjectInternal struct {
	securityGroupIdHandler
	cacheEncryptionKeyArn      *string
	cacheServiceRoleArn        *string
	cacheResourceAccessRoleArn *string
	cacheLogGroupArn           *string
	cacheVpcId                 *string
	cacheSubnetIds             []string
	region                     string
	accountID                  string
}

func (a *mqlAwsCodebuildProject) resourceAccessRole() (*mqlAwsIamRole, error) {
	if a.cacheResourceAccessRoleArn == nil || *a.cacheResourceAccessRoleArn == "" {
		a.ResourceAccessRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheResourceAccessRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsCodebuildProject) encryptionKey() (*mqlAwsKmsKey, error) {
	if a.cacheEncryptionKeyArn != nil && *a.cacheEncryptionKeyArn != "" {
		mqlKeyResource, err := NewResource(a.MqlRuntime, "aws.kms.key",
			map[string]*llx.RawData{"arn": llx.StringData(*a.cacheEncryptionKeyArn)},
		)
		if err != nil {
			return nil, err
		}
		return mqlKeyResource.(*mqlAwsKmsKey), nil
	}
	a.EncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsCodebuildProject) serviceIamRole() (*mqlAwsIamRole, error) {
	if a.cacheServiceRoleArn == nil || *a.cacheServiceRoleArn == "" {
		a.ServiceIamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheServiceRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsCodebuildProject) logsCloudWatchLogGroup() (*mqlAwsCloudwatchLoggroup, error) {
	if a.cacheLogGroupArn == nil || *a.cacheLogGroupArn == "" {
		a.LogsCloudWatchLogGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.cloudwatch.loggroup",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheLogGroupArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCloudwatchLoggroup), nil
}

func (a *mqlAwsCodebuildProject) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == nil || *a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	vpcArn := fmt.Sprintf(vpcArnPattern, a.region, a.accountID, *a.cacheVpcId)
	res, err := NewResource(a.MqlRuntime, "aws.vpc",
		map[string]*llx.RawData{"arn": llx.StringData(vpcArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

func (a *mqlAwsCodebuildProject) subnets() ([]any, error) {
	if len(a.cacheSubnetIds) == 0 {
		return []any{}, nil
	}
	res := []any{}
	for _, subnetId := range a.cacheSubnetIds {
		subnetArn := fmt.Sprintf(subnetArnPattern, a.region, a.accountID, subnetId)
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{"arn": llx.StringData(subnetArn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsCodebuildProject) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsCodebuildProject) artifactsBucket() (*mqlAwsS3Bucket, error) {
	return codebuildBucketRef(a.MqlRuntime, a.ArtifactsLocation.Data, &a.ArtifactsBucket)
}

func (a *mqlAwsCodebuildProject) cacheBucket() (*mqlAwsS3Bucket, error) {
	return codebuildBucketRef(a.MqlRuntime, a.CacheLocation.Data, &a.CacheBucket)
}

func (a *mqlAwsCodebuildProject) logsS3Bucket() (*mqlAwsS3Bucket, error) {
	return codebuildBucketRef(a.MqlRuntime, a.LogsS3Location.Data, &a.LogsS3Bucket)
}

// codebuildBucketName extracts the S3 bucket name from a CodeBuild location
// string, which is a bare "bucket" or "bucket/prefix" (and tolerates an
// optional s3:// scheme). Returns "" when no bucket is present.
func codebuildBucketName(location string) string {
	location = strings.TrimPrefix(location, "s3://")
	if location == "" {
		return ""
	}
	return strings.SplitN(location, "/", 2)[0]
}

// codebuildBucketRef resolves an S3 location string to a typed aws.s3.bucket,
// marking the field null when the location holds no bucket.
func codebuildBucketRef(runtime *plugin.Runtime, location string, tv *plugin.TValue[*mqlAwsS3Bucket]) (*mqlAwsS3Bucket, error) {
	bucket := codebuildBucketName(location)
	if bucket == "" {
		tv.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(runtime, "aws.s3.bucket",
		map[string]*llx.RawData{"name": llx.StringData(bucket)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

// ===== reportGroups =====

func (a *mqlAwsCodebuild) reportGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getReportGroups(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsCodebuild) getReportGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Codebuild(region)
			ctx := context.Background()

			res := []any{}
			arns := []string{}
			paginator := codebuild.NewListReportGroupsPaginator(svc, &codebuild.ListReportGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				arns = append(arns, page.ReportGroups...)
			}

			// BatchGetReportGroups accepts up to 100 ARNs per call
			for start := 0; start < len(arns); start += 100 {
				end := start + 100
				if end > len(arns) {
					end = len(arns)
				}
				batch, err := svc.BatchGetReportGroups(ctx, &codebuild.BatchGetReportGroupsInput{
					ReportGroupArns: arns[start:end],
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing report groups for AWS API")
						return res, nil
					}
					return nil, err
				}
				for i := range batch.ReportGroups {
					mqlRG, err := newMqlAwsCodebuildReportGroup(a.MqlRuntime, region, batch.ReportGroups[i])
					if err != nil {
						return nil, err
					}
					res = append(res, mqlRG)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsCodebuildReportGroup(runtime *plugin.Runtime, region string, rg cbtypes.ReportGroup) (plugin.Resource, error) {
	exportType := ""
	var exportS3 map[string]any
	var exportBucket, exportEncryptionKey string
	if rg.ExportConfig != nil {
		exportType = string(rg.ExportConfig.ExportConfigType)
		if rg.ExportConfig.S3Destination != nil {
			s3d := rg.ExportConfig.S3Destination
			exportBucket = convert.ToValue(s3d.Bucket)
			exportEncryptionKey = convert.ToValue(s3d.EncryptionKey)
			exportS3 = map[string]any{
				"bucket":             exportBucket,
				"bucketOwner":        convert.ToValue(s3d.BucketOwner),
				"encryptionDisabled": s3d.EncryptionDisabled != nil && *s3d.EncryptionDisabled,
				"encryptionKey":      exportEncryptionKey,
				"packaging":          string(s3d.Packaging),
				"path":               convert.ToValue(s3d.Path),
			}
		}
	}
	args := map[string]*llx.RawData{
		"__id":             llx.StringDataPtr(rg.Arn),
		"arn":              llx.StringDataPtr(rg.Arn),
		"name":             llx.StringDataPtr(rg.Name),
		"type":             llx.StringData(string(rg.Type)),
		"status":           llx.StringData(string(rg.Status)),
		"exportConfigType": llx.StringData(exportType),
		"exportConfigS3":   llx.MapData(exportS3, types.String),
		"createdAt":        llx.TimeDataPtr(rg.Created),
		"modifiedAt":       llx.TimeDataPtr(rg.LastModified),
		"region":           llx.StringData(region),
		"tags":             llx.MapData(cbTagsToMap(rg.Tags), types.String),
	}
	obj, err := CreateResource(runtime, "aws.codebuild.reportGroup", args)
	if err != nil {
		return nil, err
	}
	mqlRg := obj.(*mqlAwsCodebuildReportGroup)
	mqlRg.cacheExportBucket = exportBucket
	mqlRg.cacheExportEncryptionKey = exportEncryptionKey
	return mqlRg, nil
}

type mqlAwsCodebuildReportGroupInternal struct {
	cacheExportBucket        string
	cacheExportEncryptionKey string
}

func (a *mqlAwsCodebuildReportGroup) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsCodebuildReportGroup) exportBucket() (*mqlAwsS3Bucket, error) {
	if a.cacheExportBucket == "" {
		a.ExportBucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.s3.bucket",
		map[string]*llx.RawData{"name": llx.StringData(a.cacheExportBucket)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsCodebuildReportGroup) exportEncryptionKey() (*mqlAwsKmsKey, error) {
	if a.cacheExportEncryptionKey == "" {
		a.ExportEncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheExportEncryptionKey)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

// ===== helpers =====

func cbTagsToMap(tags []cbtypes.Tag) map[string]any {
	return tagsToMap(tags, func(t cbtypes.Tag) *string { return t.Key }, func(t cbtypes.Tag) *string { return t.Value })
}

func cbArtifactsToDicts(arts []cbtypes.ProjectArtifacts) ([]any, error) {
	res := make([]any, 0, len(arts))
	for i := range arts {
		d, err := convert.JsonToDict(arts[i])
		if err != nil {
			return nil, err
		}
		res = append(res, d)
	}
	return res, nil
}

func stringsToInterface(s []string) []any {
	res := make([]any, 0, len(s))
	for _, v := range s {
		res = append(res, v)
	}
	return res
}

func artifactsTypeString(a *cbtypes.ProjectArtifacts) string {
	if a == nil {
		return ""
	}
	return string(a.Type)
}

func artifactsNamespaceString(a *cbtypes.ProjectArtifacts) string {
	if a == nil {
		return ""
	}
	return string(a.NamespaceType)
}

func artifactsPackagingString(a *cbtypes.ProjectArtifacts) string {
	if a == nil {
		return ""
	}
	return string(a.Packaging)
}

func artifactsBucketOwnerAccessString(a *cbtypes.ProjectArtifacts) string {
	if a == nil {
		return ""
	}
	return string(a.BucketOwnerAccess)
}

func artifactsField(a *cbtypes.ProjectArtifacts, get func(*cbtypes.ProjectArtifacts) *string) string {
	if a == nil {
		return ""
	}
	v := get(a)
	if v == nil {
		return ""
	}
	return *v
}

func artifactsBoolField(a *cbtypes.ProjectArtifacts, get func(*cbtypes.ProjectArtifacts) *bool) bool {
	if a == nil {
		return false
	}
	v := get(a)
	if v == nil {
		return false
	}
	return *v
}
