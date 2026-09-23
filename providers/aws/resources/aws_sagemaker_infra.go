// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	smtypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

// ---- Init functions for cross-referenced resources ----

func initAwsSagemakerImage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to resolve sagemaker image")
	}
	arnVal := args["arn"].Value.(string)

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetImages()
	if rawResources.Error == nil {
		for _, rawResource := range rawResources.Data {
			img := rawResource.(*mqlAwsSagemakerImage)
			if img.Arn.Data == arnVal {
				return args, img, nil
			}
		}
	}

	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.sagemaker.image with arn %q not found", arnVal)
}

func initAwsSagemakerImageVersion(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to resolve sagemaker image version")
	}
	arnVal := args["arn"].Value.(string)

	// ARN format: arn:aws:sagemaker:<region>:<account>:image-version/<image-name>/<version>
	parts := strings.Split(arnVal, ":")
	if len(parts) < 6 {
		return args, nil, nil
	}
	region := parts[3]
	res := strings.TrimPrefix(parts[5], "image-version/")
	segs := strings.SplitN(res, "/", 2)
	if len(segs) < 2 {
		return args, nil, nil
	}
	imageName := segs[0]
	versionNum, err := strconv.Atoi(segs[1])
	if err != nil {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(region)
	ctx := context.Background()
	v := int32(versionNum)
	resp, err := svc.DescribeImageVersion(ctx, &sagemaker.DescribeImageVersionInput{
		ImageName: &imageName,
		Version:   &v,
	})
	if err != nil {
		return args, nil, err
	}

	args["version"] = llx.IntData(int64(versionNum))
	args["region"] = llx.StringData(region)
	args["imageName"] = llx.StringData(imageName)
	args["status"] = llx.StringData(string(resp.ImageVersionStatus))
	args["createdAt"] = llx.TimeDataPtr(resp.CreationTime)
	args["lastModifiedAt"] = llx.TimeDataPtr(resp.LastModifiedTime)
	return args, nil, nil
}

func initAwsSagemakerUserProfile(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to resolve sagemaker user profile")
	}
	arnVal := args["arn"].Value.(string)

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetUserProfiles()
	if rawResources.Error == nil {
		for _, rawResource := range rawResources.Data {
			up := rawResource.(*mqlAwsSagemakerUserProfile)
			if up.Arn.Data == arnVal {
				return args, up, nil
			}
		}
	}

	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.sagemaker.userProfile with arn %q not found", arnVal)
}

func initAwsSagemakerSpace(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to resolve sagemaker space")
	}
	arnVal := args["arn"].Value.(string)

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetSpaces()
	if rawResources.Error == nil {
		for _, rawResource := range rawResources.Data {
			sp := rawResource.(*mqlAwsSagemakerSpace)
			if sp.Arn.Data == arnVal {
				return args, sp, nil
			}
		}
	}

	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.sagemaker.space with arn %q not found", arnVal)
}

// ---- Apps ----

func (a *mqlAwsSagemaker) apps() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getApps(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getApps(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	accountID := conn.AccountId()

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListAppsPaginator(svc, &sagemaker.ListAppsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, app := range page.Apps {
					appName := convert.ToValue(app.AppName)
					domainID := convert.ToValue(app.DomainId)
					appType := string(app.AppType)
					scopeName := convert.ToValue(app.UserProfileName)
					if scopeName == "" {
						scopeName = convert.ToValue(app.SpaceName)
					}

					// App ARN: arn:aws:sagemaker:<region>:<account>:app/<domain-id>/<user-profile-or-space>/<app-type>/<app-name>
					arnVal := fmt.Sprintf("arn:aws:sagemaker:%s:%s:app/%s/%s/%s/%s",
						region, accountID, domainID, scopeName, appType, appName)

					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, &arnVal)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					mqlApp, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerApp,
						map[string]*llx.RawData{
							"arn":             llx.StringData(arnVal),
							"name":            llx.StringData(appName),
							"appType":         llx.StringData(appType),
							"region":          llx.StringData(region),
							"status":          llx.StringData(string(app.Status)),
							"createdAt":       llx.TimeDataPtr(app.CreationTime),
							"domainId":        llx.StringData(domainID),
							"userProfileName": llx.StringDataPtr(app.UserProfileName),
							"spaceName":       llx.StringDataPtr(app.SpaceName),
						})
					if err != nil {
						return nil, err
					}

					// Cache resource spec for lazy accessors (avoids DescribeApp for basic image fields).
					mqlA := mqlApp.(*mqlAwsSagemakerApp)
					if app.ResourceSpec != nil {
						mqlA.cacheInstanceType = string(app.ResourceSpec.InstanceType)
						mqlA.cacheImageArn = convert.ToValue(app.ResourceSpec.SageMakerImageArn)
						mqlA.cacheImageVersionArn = convert.ToValue(app.ResourceSpec.SageMakerImageVersionArn)
						mqlA.hasResourceSpec = true
					}
					if eagerTags != nil {
						mqlA.cacheTags = eagerTags
						mqlA.tagsFetched = true
					}

					res = append(res, mqlApp)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerAppInternal struct {
	sagemakerTagsCache
	detailsFetched          bool
	detailsLock             sync.Mutex
	cacheFailureReason      string
	cacheLastHealthCheckAt  *time.Time
	cacheLastUserActivityAt *time.Time
	hasResourceSpec         bool
	cacheImageArn           string
	cacheImageVersionArn    string
	cacheInstanceType       string
}

func (a *mqlAwsSagemakerApp) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerApp) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()

	domainID := a.DomainId.Data
	appType := a.AppType.Data
	appName := a.Name.Data
	input := &sagemaker.DescribeAppInput{
		DomainId: &domainID,
		AppType:  smAppType(appType),
		AppName:  &appName,
	}
	if up := a.UserProfileName.Data; up != "" {
		input.UserProfileName = &up
	} else if sp := a.SpaceName.Data; sp != "" {
		input.SpaceName = &sp
	}
	resp, err := svc.DescribeApp(ctx, input)
	if err != nil {
		return err
	}

	a.cacheFailureReason = convert.ToValue(resp.FailureReason)
	a.cacheLastHealthCheckAt = resp.LastHealthCheckTimestamp
	a.cacheLastUserActivityAt = resp.LastUserActivityTimestamp
	if resp.ResourceSpec != nil {
		a.hasResourceSpec = true
		a.cacheInstanceType = string(resp.ResourceSpec.InstanceType)
		a.cacheImageArn = convert.ToValue(resp.ResourceSpec.SageMakerImageArn)
		a.cacheImageVersionArn = convert.ToValue(resp.ResourceSpec.SageMakerImageVersionArn)
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerApp) failureReason() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheFailureReason, nil
}

func (a *mqlAwsSagemakerApp) lastHealthCheckAt() (*time.Time, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheLastHealthCheckAt == nil {
		a.LastHealthCheckAt.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return a.cacheLastHealthCheckAt, nil
}

func (a *mqlAwsSagemakerApp) lastUserActivityAt() (*time.Time, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheLastUserActivityAt == nil {
		a.LastUserActivityAt.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return a.cacheLastUserActivityAt, nil
}

func (a *mqlAwsSagemakerApp) sageMakerImageArn() (string, error) {
	if !a.hasResourceSpec {
		if err := a.fetchDetails(); err != nil {
			return "", err
		}
	}
	return a.cacheImageArn, nil
}

func (a *mqlAwsSagemakerApp) sageMakerImageVersionArn() (string, error) {
	if !a.hasResourceSpec {
		if err := a.fetchDetails(); err != nil {
			return "", err
		}
	}
	return a.cacheImageVersionArn, nil
}

func (a *mqlAwsSagemakerApp) instanceType() (string, error) {
	if !a.hasResourceSpec {
		if err := a.fetchDetails(); err != nil {
			return "", err
		}
	}
	return a.cacheInstanceType, nil
}

func (a *mqlAwsSagemakerApp) domain() (*mqlAwsSagemakerDomain, error) {
	domainID := a.DomainId.Data
	if domainID == "" {
		a.Domain.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	domainArn := fmt.Sprintf("arn:aws:sagemaker:%s:%s:domain/%s", a.Region.Data, conn.AccountId(), domainID)
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.domain",
		map[string]*llx.RawData{"arn": llx.StringData(domainArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerDomain), nil
}

func (a *mqlAwsSagemakerApp) userProfile() (*mqlAwsSagemakerUserProfile, error) {
	up := a.UserProfileName.Data
	if up == "" {
		a.UserProfile.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnVal := fmt.Sprintf("arn:aws:sagemaker:%s:%s:user-profile/%s/%s",
		a.Region.Data, conn.AccountId(), a.DomainId.Data, up)
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.userProfile",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerUserProfile), nil
}

func (a *mqlAwsSagemakerApp) space() (*mqlAwsSagemakerSpace, error) {
	sp := a.SpaceName.Data
	if sp == "" {
		a.Space.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnVal := fmt.Sprintf("arn:aws:sagemaker:%s:%s:space/%s/%s",
		a.Region.Data, conn.AccountId(), a.DomainId.Data, sp)
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.space",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerSpace), nil
}

func (a *mqlAwsSagemakerApp) sageMakerImage() (*mqlAwsSagemakerImage, error) {
	if !a.hasResourceSpec {
		if err := a.fetchDetails(); err != nil {
			return nil, err
		}
	}
	if a.cacheImageArn == "" {
		a.SageMakerImage.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.image",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheImageArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerImage), nil
}

func (a *mqlAwsSagemakerApp) sageMakerImageVersion() (*mqlAwsSagemakerImageVersion, error) {
	if !a.hasResourceSpec {
		if err := a.fetchDetails(); err != nil {
			return nil, err
		}
	}
	if a.cacheImageVersionArn == "" {
		a.SageMakerImageVersion.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.image.version",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheImageVersionArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerImageVersion), nil
}

func (a *mqlAwsSagemakerApp) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

// ---- App Image Configs ----

func (a *mqlAwsSagemaker) appImageConfigs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAppImageConfigs(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getAppImageConfigs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListAppImageConfigsPaginator(svc, &sagemaker.ListAppImageConfigsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, c := range page.AppImageConfigs {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, c.AppImageConfigArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					mqlCfg, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerAppImageConfig,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(c.AppImageConfigArn),
							"name":           llx.StringDataPtr(c.AppImageConfigName),
							"region":         llx.StringData(region),
							"createdAt":      llx.TimeDataPtr(c.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(c.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}

					// List response already includes the full configs — cache immediately
					mqlC := mqlCfg.(*mqlAwsSagemakerAppImageConfig)
					if c.KernelGatewayImageConfig != nil {
						if d, err := convert.JsonToDict(c.KernelGatewayImageConfig); err == nil {
							mqlC.cacheKernelGatewayImageConfig = d
						}
					}
					if c.JupyterLabAppImageConfig != nil {
						if d, err := convert.JsonToDict(c.JupyterLabAppImageConfig); err == nil {
							mqlC.cacheJupyterLabImageConfig = d
						}
					}
					if c.CodeEditorAppImageConfig != nil {
						if d, err := convert.JsonToDict(c.CodeEditorAppImageConfig); err == nil {
							mqlC.cacheCodeEditorImageConfig = d
						}
					}
					mqlC.configsLoaded = true
					if eagerTags != nil {
						mqlC.cacheTags = eagerTags
						mqlC.tagsFetched = true
					}

					res = append(res, mqlCfg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerAppImageConfigInternal struct {
	sagemakerTagsCache
	detailsLock                   sync.Mutex
	configsLoaded                 bool
	cacheKernelGatewayImageConfig any
	cacheJupyterLabImageConfig    any
	cacheCodeEditorImageConfig    any
}

func (a *mqlAwsSagemakerAppImageConfig) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerAppImageConfig) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerAppImageConfig) loadConfigs() error {
	if a.configsLoaded {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.configsLoaded {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeAppImageConfig(ctx, &sagemaker.DescribeAppImageConfigInput{AppImageConfigName: &name})
	if err != nil {
		return err
	}
	if resp.KernelGatewayImageConfig != nil {
		if d, err := convert.JsonToDict(resp.KernelGatewayImageConfig); err == nil {
			a.cacheKernelGatewayImageConfig = d
		}
	}
	if resp.JupyterLabAppImageConfig != nil {
		if d, err := convert.JsonToDict(resp.JupyterLabAppImageConfig); err == nil {
			a.cacheJupyterLabImageConfig = d
		}
	}
	if resp.CodeEditorAppImageConfig != nil {
		if d, err := convert.JsonToDict(resp.CodeEditorAppImageConfig); err == nil {
			a.cacheCodeEditorImageConfig = d
		}
	}
	a.configsLoaded = true
	return nil
}

func (a *mqlAwsSagemakerAppImageConfig) kernelGatewayImageConfig() (any, error) {
	if err := a.loadConfigs(); err != nil {
		return nil, err
	}
	return a.cacheKernelGatewayImageConfig, nil
}

func (a *mqlAwsSagemakerAppImageConfig) jupyterLabAppImageConfig() (any, error) {
	if err := a.loadConfigs(); err != nil {
		return nil, err
	}
	return a.cacheJupyterLabImageConfig, nil
}

func (a *mqlAwsSagemakerAppImageConfig) codeEditorAppImageConfig() (any, error) {
	if err := a.loadConfigs(); err != nil {
		return nil, err
	}
	return a.cacheCodeEditorImageConfig, nil
}

// ---- Studio Lifecycle Configs ----

func (a *mqlAwsSagemaker) studioLifecycleConfigs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getStudioLifecycleConfigs(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getStudioLifecycleConfigs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListStudioLifecycleConfigsPaginator(svc, &sagemaker.ListStudioLifecycleConfigsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, c := range page.StudioLifecycleConfigs {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, c.StudioLifecycleConfigArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					mqlCfg, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerStudioLifecycleConfig,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(c.StudioLifecycleConfigArn),
							"name":           llx.StringDataPtr(c.StudioLifecycleConfigName),
							"region":         llx.StringData(region),
							"appType":        llx.StringData(string(c.StudioLifecycleConfigAppType)),
							"createdAt":      llx.TimeDataPtr(c.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(c.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					m := mqlCfg.(*mqlAwsSagemakerStudioLifecycleConfig)
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched = true
					}
					res = append(res, mqlCfg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerStudioLifecycleConfigInternal struct {
	sagemakerTagsCache
	contentLock    sync.Mutex
	contentFetched bool
	cacheContent   string
}

func (a *mqlAwsSagemakerStudioLifecycleConfig) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerStudioLifecycleConfig) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerStudioLifecycleConfig) content() (string, error) {
	if a.contentFetched {
		return a.cacheContent, nil
	}
	a.contentLock.Lock()
	defer a.contentLock.Unlock()
	if a.contentFetched {
		return a.cacheContent, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeStudioLifecycleConfig(ctx, &sagemaker.DescribeStudioLifecycleConfigInput{
		StudioLifecycleConfigName: &name,
	})
	if err != nil {
		return "", err
	}
	a.cacheContent = convert.ToValue(resp.StudioLifecycleConfigContent)
	a.contentFetched = true
	return a.cacheContent, nil
}

// ---- Code Repositories ----

func (a *mqlAwsSagemaker) codeRepositories() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getCodeRepositories(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getCodeRepositories(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListCodeRepositoriesPaginator(svc, &sagemaker.ListCodeRepositoriesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, c := range page.CodeRepositorySummaryList {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, c.CodeRepositoryArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					mqlRepo, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerCodeRepository,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(c.CodeRepositoryArn),
							"name":           llx.StringDataPtr(c.CodeRepositoryName),
							"region":         llx.StringData(region),
							"createdAt":      llx.TimeDataPtr(c.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(c.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					// Summary already includes GitConfig
					m := mqlRepo.(*mqlAwsSagemakerCodeRepository)
					if c.GitConfig != nil {
						m.cacheRepositoryUrl = convert.ToValue(c.GitConfig.RepositoryUrl)
						m.cacheBranch = convert.ToValue(c.GitConfig.Branch)
						m.cacheSecretArn = c.GitConfig.SecretArn
						m.gitConfigLoaded = true
					}
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched = true
					}
					res = append(res, mqlRepo)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerCodeRepositoryInternal struct {
	sagemakerTagsCache
	gitConfigLock      sync.Mutex
	gitConfigLoaded    bool
	cacheRepositoryUrl string
	cacheBranch        string
	cacheSecretArn     *string
}

func (a *mqlAwsSagemakerCodeRepository) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerCodeRepository) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerCodeRepository) loadGitConfig() error {
	if a.gitConfigLoaded {
		return nil
	}
	a.gitConfigLock.Lock()
	defer a.gitConfigLock.Unlock()
	if a.gitConfigLoaded {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeCodeRepository(ctx, &sagemaker.DescribeCodeRepositoryInput{CodeRepositoryName: &name})
	if err != nil {
		return err
	}
	if resp.GitConfig != nil {
		a.cacheRepositoryUrl = convert.ToValue(resp.GitConfig.RepositoryUrl)
		a.cacheBranch = convert.ToValue(resp.GitConfig.Branch)
		a.cacheSecretArn = resp.GitConfig.SecretArn
	}
	a.gitConfigLoaded = true
	return nil
}

func (a *mqlAwsSagemakerCodeRepository) repositoryUrl() (string, error) {
	if err := a.loadGitConfig(); err != nil {
		return "", err
	}
	return a.cacheRepositoryUrl, nil
}

func (a *mqlAwsSagemakerCodeRepository) branch() (string, error) {
	if err := a.loadGitConfig(); err != nil {
		return "", err
	}
	return a.cacheBranch, nil
}

func (a *mqlAwsSagemakerCodeRepository) secret() (*mqlAwsSecretsmanagerSecret, error) {
	if err := a.loadGitConfig(); err != nil {
		return nil, err
	}
	if a.cacheSecretArn == nil || *a.cacheSecretArn == "" {
		a.Secret.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.secretsmanager.secret",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheSecretArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSecretsmanagerSecret), nil
}

// ---- Notebook Instance Lifecycle Configs ----

func (a *mqlAwsSagemaker) notebookInstanceLifecycleConfigs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getNotebookInstanceLifecycleConfigs(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getNotebookInstanceLifecycleConfigs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListNotebookInstanceLifecycleConfigsPaginator(svc, &sagemaker.ListNotebookInstanceLifecycleConfigsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, c := range page.NotebookInstanceLifecycleConfigs {
					mqlCfg, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerNotebookInstanceLifecycleConfig,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(c.NotebookInstanceLifecycleConfigArn),
							"name":           llx.StringDataPtr(c.NotebookInstanceLifecycleConfigName),
							"region":         llx.StringData(region),
							"createdAt":      llx.TimeDataPtr(c.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(c.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCfg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerNotebookInstanceLifecycleConfigInternal struct {
	hooksLock     sync.Mutex
	hooksFetched  bool
	cacheOnCreate []any
	cacheOnStart  []any
}

func (a *mqlAwsSagemakerNotebookInstanceLifecycleConfig) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerNotebookInstanceLifecycleConfig) fetchHooks() error {
	if a.hooksFetched {
		return nil
	}
	a.hooksLock.Lock()
	defer a.hooksLock.Unlock()
	if a.hooksFetched {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeNotebookInstanceLifecycleConfig(ctx, &sagemaker.DescribeNotebookInstanceLifecycleConfigInput{
		NotebookInstanceLifecycleConfigName: &name,
	})
	if err != nil {
		return err
	}
	for _, h := range resp.OnCreate {
		if h.Content != nil {
			a.cacheOnCreate = append(a.cacheOnCreate, *h.Content)
		}
	}
	for _, h := range resp.OnStart {
		if h.Content != nil {
			a.cacheOnStart = append(a.cacheOnStart, *h.Content)
		}
	}
	a.hooksFetched = true
	return nil
}

func (a *mqlAwsSagemakerNotebookInstanceLifecycleConfig) onCreate() ([]any, error) {
	if err := a.fetchHooks(); err != nil {
		return nil, err
	}
	return a.cacheOnCreate, nil
}

func (a *mqlAwsSagemakerNotebookInstanceLifecycleConfig) onStart() ([]any, error) {
	if err := a.fetchHooks(); err != nil {
		return nil, err
	}
	return a.cacheOnStart, nil
}

// ---- Images ----

func (a *mqlAwsSagemaker) images() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getImages(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getImages(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListImagesPaginator(svc, &sagemaker.ListImagesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, img := range page.Images {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, img.ImageArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					mqlImg, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerImage,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(img.ImageArn),
							"name":           llx.StringDataPtr(img.ImageName),
							"region":         llx.StringData(region),
							"displayName":    llx.StringDataPtr(img.DisplayName),
							"description":    llx.StringDataPtr(img.Description),
							"status":         llx.StringData(string(img.ImageStatus)),
							"createdAt":      llx.TimeDataPtr(img.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(img.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					m := mqlImg.(*mqlAwsSagemakerImage)
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched = true
					}
					res = append(res, mqlImg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerImageInternal struct {
	sagemakerTagsCache
	detailsLock        sync.Mutex
	detailsFetched     bool
	cacheFailureReason string
	cacheRoleArn       *string
}

func (a *mqlAwsSagemakerImage) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerImage) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerImage) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeImage(ctx, &sagemaker.DescribeImageInput{ImageName: &name})
	if err != nil {
		return err
	}
	a.cacheFailureReason = convert.ToValue(resp.FailureReason)
	a.cacheRoleArn = resp.RoleArn
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerImage) failureReason() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheFailureReason, nil
}

func (a *mqlAwsSagemakerImage) iamRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerImage) versions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data

	res := []any{}
	paginator := sagemaker.NewListImageVersionsPaginator(svc, &sagemaker.ListImageVersionsInput{ImageName: &name})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "sagemaker:ListImageVersions")
		}
		for _, v := range page.ImageVersions {
			var versionNum int64
			if v.Version != nil {
				versionNum = int64(*v.Version)
			}
			mqlV, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerImageVersion,
				map[string]*llx.RawData{
					"arn":            llx.StringDataPtr(v.ImageVersionArn),
					"version":        llx.IntData(versionNum),
					"region":         llx.StringData(a.Region.Data),
					"imageName":      llx.StringData(name),
					"status":         llx.StringData(string(v.ImageVersionStatus)),
					"createdAt":      llx.TimeDataPtr(v.CreationTime),
					"lastModifiedAt": llx.TimeDataPtr(v.LastModifiedTime),
				})
			if err != nil {
				return nil, err
			}
			mqlIV := mqlV.(*mqlAwsSagemakerImageVersion)
			mqlIV.cacheVersionNumber = int32(versionNum)
			res = append(res, mqlV)
		}
	}
	return res, nil
}

type mqlAwsSagemakerImageVersionInternal struct {
	detailsLock        sync.Mutex
	detailsFetched     bool
	cacheVersionNumber int32
	cacheContainerImg  string
	cacheBaseImage     string
}

func (a *mqlAwsSagemakerImageVersion) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerImageVersion) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	imageName := a.ImageName.Data
	input := &sagemaker.DescribeImageVersionInput{ImageName: &imageName}
	if a.cacheVersionNumber > 0 {
		v := a.cacheVersionNumber
		input.Version = &v
	}
	resp, err := svc.DescribeImageVersion(ctx, input)
	if err != nil {
		return err
	}
	a.cacheContainerImg = convert.ToValue(resp.ContainerImage)
	a.cacheBaseImage = convert.ToValue(resp.BaseImage)
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerImageVersion) containerImage() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheContainerImg, nil
}

func (a *mqlAwsSagemakerImageVersion) baseImage() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheBaseImage, nil
}

// imageArn is derivable from the parent image; we expose via the existing imageName + arn
// but keep the underlying image ARN available to consumers if they need it.
// (Schema exposes `imageName` for lookup; the parent image's ARN is available via the
// arn prefix of the version ARN itself.)

// ---- Algorithms ----

func (a *mqlAwsSagemaker) algorithms() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAlgorithms(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getAlgorithms(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListAlgorithmsPaginator(svc, &sagemaker.ListAlgorithmsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, alg := range page.AlgorithmSummaryList {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, alg.AlgorithmArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					mqlAlg, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerAlgorithm,
						map[string]*llx.RawData{
							"arn":         llx.StringDataPtr(alg.AlgorithmArn),
							"name":        llx.StringDataPtr(alg.AlgorithmName),
							"region":      llx.StringData(region),
							"description": llx.StringDataPtr(alg.AlgorithmDescription),
							"status":      llx.StringData(string(alg.AlgorithmStatus)),
							"createdAt":   llx.TimeDataPtr(alg.CreationTime),
						})
					if err != nil {
						return nil, err
					}
					m := mqlAlg.(*mqlAwsSagemakerAlgorithm)
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched = true
					}
					res = append(res, mqlAlg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerAlgorithmInternal struct {
	sagemakerTagsCache
	detailsLock                          sync.Mutex
	detailsFetched                       bool
	cacheTrainingImage                   string
	cacheSupportedContentTypes           []any
	cacheSupportedTransformInstanceTypes []any
	cacheSupportedTrainingInstanceTypes  []any
	cacheSupportsDistributedTraining     bool
}

func (a *mqlAwsSagemakerAlgorithm) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerAlgorithm) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerAlgorithm) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeAlgorithm(ctx, &sagemaker.DescribeAlgorithmInput{AlgorithmName: &name})
	if err != nil {
		return err
	}
	if ts := resp.TrainingSpecification; ts != nil {
		a.cacheTrainingImage = convert.ToValue(ts.TrainingImage)
		if ts.SupportsDistributedTraining != nil {
			a.cacheSupportsDistributedTraining = *ts.SupportsDistributedTraining
		}
		for _, t := range ts.SupportedTrainingInstanceTypes {
			a.cacheSupportedTrainingInstanceTypes = append(a.cacheSupportedTrainingInstanceTypes, string(t))
		}
		seenContent := map[string]struct{}{}
		for _, ch := range ts.TrainingChannels {
			for _, ct := range ch.SupportedContentTypes {
				if _, ok := seenContent[ct]; ok {
					continue
				}
				seenContent[ct] = struct{}{}
				a.cacheSupportedContentTypes = append(a.cacheSupportedContentTypes, ct)
			}
		}
	}
	if is := resp.InferenceSpecification; is != nil {
		for _, t := range is.SupportedTransformInstanceTypes {
			a.cacheSupportedTransformInstanceTypes = append(a.cacheSupportedTransformInstanceTypes, string(t))
		}
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerAlgorithm) trainingImage() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheTrainingImage, nil
}

func (a *mqlAwsSagemakerAlgorithm) supportedContentTypes() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheSupportedContentTypes, nil
}

func (a *mqlAwsSagemakerAlgorithm) supportedTransformInstanceTypes() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheSupportedTransformInstanceTypes, nil
}

func (a *mqlAwsSagemakerAlgorithm) supportedTrainingInstanceTypes() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheSupportedTrainingInstanceTypes, nil
}

func (a *mqlAwsSagemakerAlgorithm) supportsDistributedTraining() (bool, error) {
	if err := a.fetchDetails(); err != nil {
		return false, err
	}
	return a.cacheSupportsDistributedTraining, nil
}

// ---- Compilation Jobs ----

func (a *mqlAwsSagemaker) compilationJobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getCompilationJobs(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getCompilationJobs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListCompilationJobsPaginator(svc, &sagemaker.ListCompilationJobsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, job := range page.CompilationJobSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, job.CompilationJobArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					mqlJob, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerCompilationJob,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(job.CompilationJobArn),
							"name":           llx.StringDataPtr(job.CompilationJobName),
							"region":         llx.StringData(region),
							"status":         llx.StringData(string(job.CompilationJobStatus)),
							"createdAt":      llx.TimeDataPtr(job.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(job.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					m := mqlJob.(*mqlAwsSagemakerCompilationJob)
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched = true
					}
					res = append(res, mqlJob)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerCompilationJobInternal struct {
	sagemakerTagsCache
	detailsLock              sync.Mutex
	detailsFetched           bool
	cacheStartedAt           *time.Time
	cacheEndedAt             *time.Time
	cacheFailureReason       string
	cacheRoleArn             *string
	cacheInputS3Uri          string
	cacheOutputS3Uri         string
	cacheTargetDevice        string
	cacheTargetPlatform      any
	cacheMaxRuntimeInSeconds int64
}

func (a *mqlAwsSagemakerCompilationJob) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerCompilationJob) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerCompilationJob) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeCompilationJob(ctx, &sagemaker.DescribeCompilationJobInput{CompilationJobName: &name})
	if err != nil {
		return err
	}
	a.cacheStartedAt = resp.CompilationStartTime
	a.cacheEndedAt = resp.CompilationEndTime
	a.cacheFailureReason = convert.ToValue(resp.FailureReason)
	a.cacheRoleArn = resp.RoleArn
	if resp.InputConfig != nil {
		a.cacheInputS3Uri = convert.ToValue(resp.InputConfig.S3Uri)
	}
	if resp.OutputConfig != nil {
		a.cacheOutputS3Uri = convert.ToValue(resp.OutputConfig.S3OutputLocation)
		a.cacheTargetDevice = string(resp.OutputConfig.TargetDevice)
		if resp.OutputConfig.TargetPlatform != nil {
			if d, err := convert.JsonToDict(resp.OutputConfig.TargetPlatform); err == nil {
				a.cacheTargetPlatform = d
			}
		}
	}
	if resp.StoppingCondition != nil && resp.StoppingCondition.MaxRuntimeInSeconds != nil {
		a.cacheMaxRuntimeInSeconds = int64(*resp.StoppingCondition.MaxRuntimeInSeconds)
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerCompilationJob) startedAt() (*time.Time, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheStartedAt == nil {
		a.StartedAt.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return a.cacheStartedAt, nil
}

func (a *mqlAwsSagemakerCompilationJob) endedAt() (*time.Time, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheEndedAt == nil {
		a.EndedAt.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return a.cacheEndedAt, nil
}

func (a *mqlAwsSagemakerCompilationJob) failureReason() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheFailureReason, nil
}

func (a *mqlAwsSagemakerCompilationJob) iamRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerCompilationJob) inputS3Uri() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheInputS3Uri, nil
}

func (a *mqlAwsSagemakerCompilationJob) outputS3Uri() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheOutputS3Uri, nil
}

func (a *mqlAwsSagemakerCompilationJob) targetDevice() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheTargetDevice, nil
}

func (a *mqlAwsSagemakerCompilationJob) targetPlatform() (any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheTargetPlatform, nil
}

func (a *mqlAwsSagemakerCompilationJob) maxRuntimeInSeconds() (int64, error) {
	if err := a.fetchDetails(); err != nil {
		return 0, err
	}
	return a.cacheMaxRuntimeInSeconds, nil
}

// ---- helpers ----

// smAppType converts the string form of an AppType stored in MQL into the
// typed enum DescribeApp expects.
func smAppType(s string) smtypes.AppType {
	return smtypes.AppType(s)
}
