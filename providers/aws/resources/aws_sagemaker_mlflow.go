// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

// sagemakerRegionList fans collect out over the connection's regions. A region
// that refuses the call or doesn't offer it is logged and skipped.
func sagemakerRegionList(conn *connection.AwsConnection, collect func(svc *sagemaker.Client, region string) ([]any, error)) ([]any, error) {
	regions, err := conn.Regions()
	if err != nil {
		return nil, err
	}
	tasks := make([]*jobpool.Job, 0, len(regions))
	for _, region := range regions {
		tasks = append(tasks, jobpool.NewJob(func() (jobpool.JobResult, error) {
			res, err := collect(conn.Sagemaker(region), region)
			if err != nil {
				if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return []any{}, nil
				}
				return nil, err
			}
			return jobpool.JobResult(res), nil
		}))
	}
	pool := jobpool.CreatePool(tasks, 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	res := []any{}
	for i := range pool.Jobs {
		if pool.Jobs[i].Result != nil {
			res = append(res, pool.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

// --- MLflow tracking servers ---

type mqlAwsSagemakerMlflowTrackingServerInternal struct {
	fetchLock sync.Mutex
	fetched   atomic.Bool
	detail    *sagemaker.DescribeMlflowTrackingServerOutput
}

func (a *mqlAwsSagemaker) mlflowTrackingServers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return sagemakerRegionList(conn, func(svc *sagemaker.Client, region string) ([]any, error) {
		res := []any{}
		paginator := sagemaker.NewListMlflowTrackingServersPaginator(svc, &sagemaker.ListMlflowTrackingServersInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(context.Background())
			if err != nil {
				return nil, err
			}
			for _, t := range page.TrackingServerSummaries {
				mqlT, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerMlflowTrackingServer, map[string]*llx.RawData{
					"__id":          llx.StringDataPtr(t.TrackingServerArn),
					"arn":           llx.StringDataPtr(t.TrackingServerArn),
					"name":          llx.StringDataPtr(t.TrackingServerName),
					"region":        llx.StringData(region),
					"status":        llx.StringData(string(t.TrackingServerStatus)),
					"isActive":      trackingServerActive(t.IsActive),
					"mlflowVersion": llx.StringDataPtr(t.MlflowVersion),
					"createdAt":     llx.TimeDataPtr(t.CreationTime),
					"updatedAt":     llx.TimeDataPtr(t.LastModifiedTime),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlT)
			}
		}
		return res, nil
	})
}

// trackingServerActive maps the Active/Inactive state onto a boolean, null
// when the state is not reported.
func trackingServerActive(v sagemakertypes.IsTrackingServerActive) *llx.RawData {
	switch v {
	case sagemakertypes.IsTrackingServerActiveActive:
		return llx.BoolData(true)
	case sagemakertypes.IsTrackingServerActiveInactive:
		return llx.BoolData(false)
	}
	return llx.NilData
}

func (a *mqlAwsSagemakerMlflowTrackingServer) fetchDetail() (*sagemaker.DescribeMlflowTrackingServerOutput, error) {
	if a.fetched.Load() {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	name := a.Name.Data
	out, err := conn.Sagemaker(a.Region.Data).DescribeMlflowTrackingServer(context.Background(), &sagemaker.DescribeMlflowTrackingServerInput{
		TrackingServerName: &name,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, llx.Forbidden(err, llx.WithPermissions("sagemaker:DescribeMlflowTrackingServer"))
		}
		return nil, err
	}
	a.detail = out
	a.fetched.Store(true)
	return a.detail, nil
}

func sagemakerOptString(v *string, field *plugin.TValue[string]) (string, error) {
	if convert.ToValue(v) == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *v, nil
}

func sagemakerOptBool(v *bool, field *plugin.TValue[bool]) (bool, error) {
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *v, nil
}

func (a *mqlAwsSagemakerMlflowTrackingServer) url() (string, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if d == nil {
		return sagemakerOptString(nil, &a.Url)
	}
	return sagemakerOptString(d.TrackingServerUrl, &a.Url)
}

func (a *mqlAwsSagemakerMlflowTrackingServer) iamRole() (*mqlAwsIamRole, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil || convert.ToValue(d.RoleArn) == "" {
		a.IamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsIamRole, map[string]*llx.RawData{"arn": llx.StringDataPtr(d.RoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerMlflowTrackingServer) artifactStoreUri() (string, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if d == nil {
		return sagemakerOptString(nil, &a.ArtifactStoreUri)
	}
	return sagemakerOptString(d.ArtifactStoreUri, &a.ArtifactStoreUri)
}

func (a *mqlAwsSagemakerMlflowTrackingServer) artifactStoreBucket() (*mqlAwsS3Bucket, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	uri := ""
	if d != nil {
		uri = convert.ToValue(d.ArtifactStoreUri)
	}
	return s3BucketRefFromUri(a.MqlRuntime, uri, &a.ArtifactStoreBucket)
}

func (a *mqlAwsSagemakerMlflowTrackingServer) automaticModelRegistration() (bool, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	if d == nil {
		return sagemakerOptBool(nil, &a.AutomaticModelRegistration)
	}
	return sagemakerOptBool(d.AutomaticModelRegistration, &a.AutomaticModelRegistration)
}

func (a *mqlAwsSagemakerMlflowTrackingServer) size() (string, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if d == nil || d.TrackingServerSize == "" {
		a.Size.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(d.TrackingServerSize), nil
}

func (a *mqlAwsSagemakerMlflowTrackingServer) weeklyMaintenanceWindowStart() (string, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if d == nil {
		return sagemakerOptString(nil, &a.WeeklyMaintenanceWindowStart)
	}
	return sagemakerOptString(d.WeeklyMaintenanceWindowStart, &a.WeeklyMaintenanceWindowStart)
}

// --- Partner apps ---

type mqlAwsSagemakerPartnerAppInternal struct {
	fetchLock sync.Mutex
	fetched   atomic.Bool
	detail    *sagemaker.DescribePartnerAppOutput
}

func (a *mqlAwsSagemaker) partnerApps() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return sagemakerRegionList(conn, func(svc *sagemaker.Client, region string) ([]any, error) {
		res := []any{}
		paginator := sagemaker.NewListPartnerAppsPaginator(svc, &sagemaker.ListPartnerAppsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(context.Background())
			if err != nil {
				return nil, err
			}
			for _, p := range page.Summaries {
				mqlP, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerPartnerApp, map[string]*llx.RawData{
					"__id":      llx.StringDataPtr(p.Arn),
					"arn":       llx.StringDataPtr(p.Arn),
					"name":      llx.StringDataPtr(p.Name),
					"region":    llx.StringData(region),
					"type":      llx.StringData(string(p.Type)),
					"status":    llx.StringData(string(p.Status)),
					"createdAt": llx.TimeDataPtr(p.CreationTime),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlP)
			}
		}
		return res, nil
	})
}

func (a *mqlAwsSagemakerPartnerApp) fetchDetail() (*sagemaker.DescribePartnerAppOutput, error) {
	if a.fetched.Load() {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	appArn := a.Arn.Data
	out, err := conn.Sagemaker(a.Region.Data).DescribePartnerApp(context.Background(), &sagemaker.DescribePartnerAppInput{Arn: &appArn})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, llx.Forbidden(err, llx.WithPermissions("sagemaker:DescribePartnerApp"))
		}
		return nil, err
	}
	a.detail = out
	a.fetched.Store(true)
	return a.detail, nil
}

func (a *mqlAwsSagemakerPartnerApp) authType() (string, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if d == nil || d.AuthType == "" {
		a.AuthType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(d.AuthType), nil
}

func (a *mqlAwsSagemakerPartnerApp) iamRole() (*mqlAwsIamRole, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil || convert.ToValue(d.ExecutionRoleArn) == "" {
		a.IamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsIamRole, map[string]*llx.RawData{"arn": llx.StringDataPtr(d.ExecutionRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerPartnerApp) kmsKey() (*mqlAwsKmsKey, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil || convert.ToValue(d.KmsKeyId) == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey, kmsKeyRefArgs(a.Region.Data, conn.AccountId(), *d.KmsKeyId))
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsSagemakerPartnerApp) enableIamSessionBasedIdentity() (bool, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	if d == nil {
		return sagemakerOptBool(nil, &a.EnableIamSessionBasedIdentity)
	}
	return sagemakerOptBool(d.EnableIamSessionBasedIdentity, &a.EnableIamSessionBasedIdentity)
}

func (a *mqlAwsSagemakerPartnerApp) adminUsers() ([]any, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil {
		a.AdminUsers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if d.ApplicationConfig == nil {
		return []any{}, nil
	}
	return convert.SliceAnyToInterface(d.ApplicationConfig.AdminUsers), nil
}

func (a *mqlAwsSagemakerPartnerApp) baseUrl() (string, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if d == nil {
		return sagemakerOptString(nil, &a.BaseUrl)
	}
	return sagemakerOptString(d.BaseUrl, &a.BaseUrl)
}

func (a *mqlAwsSagemakerPartnerApp) version() (string, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if d == nil {
		return sagemakerOptString(nil, &a.Version)
	}
	return sagemakerOptString(d.Version, &a.Version)
}

func (a *mqlAwsSagemakerPartnerApp) currentVersionEolDate() (*time.Time, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil || d.CurrentVersionEolDate == nil {
		a.CurrentVersionEolDate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return d.CurrentVersionEolDate, nil
}

func (a *mqlAwsSagemakerPartnerApp) autoMinorVersionUpgrade() (bool, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	if d == nil {
		return sagemakerOptBool(nil, &a.AutoMinorVersionUpgrade)
	}
	return sagemakerOptBool(d.EnableAutoMinorVersionUpgrade, &a.AutoMinorVersionUpgrade)
}

func (a *mqlAwsSagemakerPartnerApp) tier() (string, error) {
	d, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if d == nil {
		return sagemakerOptString(nil, &a.Tier)
	}
	return sagemakerOptString(d.Tier, &a.Tier)
}
