// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	mqlTypes "go.mondoo.com/mql/v13/types"
)

// ---------------- Patch groups ----------------

func (a *mqlAwsSsm) patchGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getPatchGroups(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSsm) getPatchGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			res := []any{}
			ssmsvc := conn.Ssm(region)
			ctx := context.Background()

			paginator := ssm.NewDescribePatchGroupsPaginator(ssmsvc, &ssm.DescribePatchGroupsInput{})
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather ssm patch groups")
				}

				for _, pg := range resp.Mappings {
					patchGroup := convert.ToValue(pg.PatchGroup)

					var baselineId, baselineName, osStr string
					var identity map[string]any
					if pg.BaselineIdentity != nil {
						baselineId = convert.ToValue(pg.BaselineIdentity.BaselineId)
						baselineName = convert.ToValue(pg.BaselineIdentity.BaselineName)
						osStr = string(pg.BaselineIdentity.OperatingSystem)
						identity = map[string]any{
							"baselineId":          baselineId,
							"baselineName":        baselineName,
							"baselineDescription": convert.ToValue(pg.BaselineIdentity.BaselineDescription),
							"operatingSystem":     osStr,
							"defaultBaseline":     pg.BaselineIdentity.DefaultBaseline,
						}
					}

					mqlPG, err := CreateResource(a.MqlRuntime, "aws.ssm.patchGroup",
						map[string]*llx.RawData{
							"patchGroup":       llx.StringData(patchGroup),
							"region":           llx.StringData(region),
							"baselineId":       llx.StringData(baselineId),
							"baselineName":     llx.StringData(baselineName),
							"operatingSystem":  llx.StringData(osStr),
							"baselineIdentity": llx.DictData(identity),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPG)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsSsmPatchGroup) id() (string, error) {
	return a.Region.Data + "/" + a.OperatingSystem.Data + "/" + a.PatchGroup.Data, nil
}

func (a *mqlAwsSsmPatchGroup) baseline() (*mqlAwsSsmPatchBaseline, error) {
	if a.BaselineId.Data == "" {
		a.Baseline.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arn := ssmPatchBaselineArn(a.Region.Data, conn.AccountId(), a.BaselineId.Data)
	res, err := NewResource(a.MqlRuntime, "aws.ssm.patchBaseline",
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSsmPatchBaseline), nil
}

// ---------------- Maintenance window tasks & targets ----------------

type mqlAwsSsmMaintenanceWindowInternal struct {
	detailFetched bool
	detailErr     error
	detail        *ssm.GetMaintenanceWindowOutput
	detailLock    sync.Mutex
}

// fetchDetail loads the GetMaintenanceWindow response once per window and
// caches it so callers like modifiedDate() and allowUnassociatedTargets()
// share a single API call.
func (a *mqlAwsSsmMaintenanceWindow) fetchDetail() (*ssm.GetMaintenanceWindowOutput, error) {
	if a.detailFetched {
		return a.detail, a.detailErr
	}
	a.detailLock.Lock()
	defer a.detailLock.Unlock()
	if a.detailFetched {
		return a.detail, a.detailErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ssmsvc := conn.Ssm(a.Region.Data)
	ctx := context.Background()
	windowId := a.Id.Data
	resp, err := ssmsvc.GetMaintenanceWindow(ctx, &ssm.GetMaintenanceWindowInput{
		WindowId: &windowId,
	})
	a.detail = resp
	a.detailErr = err
	a.detailFetched = true
	return a.detail, a.detailErr
}

func (a *mqlAwsSsmMaintenanceWindow) modifiedDate() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return detail.ModifiedDate, nil
}

func (a *mqlAwsSsmMaintenanceWindow) createdDate() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return detail.CreatedDate, nil
}

func (a *mqlAwsSsmMaintenanceWindow) tasks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ssmsvc := conn.Ssm(a.Region.Data)
	ctx := context.Background()

	windowId := a.Id.Data
	res := []any{}
	paginator := ssm.NewDescribeMaintenanceWindowTasksPaginator(ssmsvc, &ssm.DescribeMaintenanceWindowTasksInput{
		WindowId: &windowId,
	})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, t := range resp.Tasks {
			mqlTask, err := CreateResource(a.MqlRuntime, "aws.ssm.maintenanceWindow.task",
				map[string]*llx.RawData{
					"windowId":       llx.StringDataPtr(t.WindowId),
					"windowTaskId":   llx.StringDataPtr(t.WindowTaskId),
					"region":         llx.StringData(a.Region.Data),
					"name":           llx.StringDataPtr(t.Name),
					"description":    llx.StringDataPtr(t.Description),
					"taskType":       llx.StringData(string(t.Type)),
					"taskArn":        llx.StringDataPtr(t.TaskArn),
					"serviceRoleArn": llx.StringDataPtr(t.ServiceRoleArn),
					"priority":       llx.IntData(int64(t.Priority)),
					"maxConcurrency": llx.StringDataPtr(t.MaxConcurrency),
					"maxErrors":      llx.StringDataPtr(t.MaxErrors),
					"cutoffBehavior": llx.StringData(string(t.CutoffBehavior)),
					"targets":        llx.ArrayData(assocTargetsToDict(t.Targets), mqlTypes.Dict),
				})
			if err != nil {
				return nil, err
			}
			mw := mqlTask.(*mqlAwsSsmMaintenanceWindowTask)
			mw.cacheServiceRoleArn = t.ServiceRoleArn
			res = append(res, mqlTask)
		}
	}
	return res, nil
}

func (a *mqlAwsSsmMaintenanceWindow) targets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ssmsvc := conn.Ssm(a.Region.Data)
	ctx := context.Background()

	windowId := a.Id.Data
	res := []any{}
	paginator := ssm.NewDescribeMaintenanceWindowTargetsPaginator(ssmsvc, &ssm.DescribeMaintenanceWindowTargetsInput{
		WindowId: &windowId,
	})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, t := range resp.Targets {
			mqlTarget, err := CreateResource(a.MqlRuntime, "aws.ssm.maintenanceWindow.target",
				map[string]*llx.RawData{
					"windowId":         llx.StringDataPtr(t.WindowId),
					"windowTargetId":   llx.StringDataPtr(t.WindowTargetId),
					"region":           llx.StringData(a.Region.Data),
					"name":             llx.StringDataPtr(t.Name),
					"description":      llx.StringDataPtr(t.Description),
					"resourceType":     llx.StringData(string(t.ResourceType)),
					"ownerInformation": llx.StringDataPtr(t.OwnerInformation),
					"targets":          llx.ArrayData(assocTargetsToDict(t.Targets), mqlTypes.Dict),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTarget)
		}
	}
	return res, nil
}

type mqlAwsSsmMaintenanceWindowTaskInternal struct {
	cacheServiceRoleArn *string
}

func (a *mqlAwsSsmMaintenanceWindowTask) id() (string, error) {
	return a.Region.Data + "/" + a.WindowId.Data + "/" + a.WindowTaskId.Data, nil
}

func (a *mqlAwsSsmMaintenanceWindowTask) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheServiceRoleArn == nil || *a.cacheServiceRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheServiceRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSsmMaintenanceWindowTarget) id() (string, error) {
	return a.Region.Data + "/" + a.WindowId.Data + "/" + a.WindowTargetId.Data, nil
}

// ---------------- Association detail lazy-load ----------------

type mqlAwsSsmAssociationInternal struct {
	fetched  bool
	fetchErr error
	lock     sync.Mutex
}

func (a *mqlAwsSsmAssociation) fetchDetail() error {
	if a.fetched {
		return a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.fetchErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ssmsvc := conn.Ssm(a.Region.Data)
	ctx := context.Background()

	assocId := a.AssociationId.Data
	resp, err := ssmsvc.DescribeAssociation(ctx, &ssm.DescribeAssociationInput{
		AssociationId: &assocId,
	})
	if err != nil {
		a.fetched = true
		if Is400AccessDeniedError(err) {
			a.populateEmptyDetail()
			return nil
		}
		a.fetchErr = err
		a.populateEmptyDetail()
		return err
	}

	desc := resp.AssociationDescription
	if desc == nil {
		a.populateEmptyDetail()
		a.fetched = true
		return nil
	}

	var statusDict any
	if desc.Status != nil {
		statusDict = map[string]any{
			"date":           convert.ToValue(desc.Status.Date).Format(time.RFC3339),
			"name":           string(desc.Status.Name),
			"message":        convert.ToValue(desc.Status.Message),
			"additionalInfo": convert.ToValue(desc.Status.AdditionalInfo),
		}
	}

	a.Status = plugin.TValue[any]{Data: statusDict, State: plugin.StateIsSet}
	a.CreatedDate = plugin.TValue[*time.Time]{Data: desc.Date, State: plugin.StateIsSet}
	a.LastSuccessfulExecutionDate = plugin.TValue[*time.Time]{Data: desc.LastSuccessfulExecutionDate, State: plugin.StateIsSet}
	a.ComplianceSeverity = plugin.TValue[string]{Data: string(desc.ComplianceSeverity), State: plugin.StateIsSet}
	a.SyncCompliance = plugin.TValue[string]{Data: string(desc.SyncCompliance), State: plugin.StateIsSet}
	a.ApplyOnlyAtCronInterval = plugin.TValue[bool]{Data: desc.ApplyOnlyAtCronInterval, State: plugin.StateIsSet}
	a.MaxConcurrency = plugin.TValue[string]{Data: convert.ToValue(desc.MaxConcurrency), State: plugin.StateIsSet}
	a.MaxErrors = plugin.TValue[string]{Data: convert.ToValue(desc.MaxErrors), State: plugin.StateIsSet}
	a.LastUpdatedAt = plugin.TValue[*time.Time]{Data: desc.LastUpdateAssociationDate, State: plugin.StateIsSet}
	a.CalendarNames = plugin.TValue[[]any]{Data: convert.SliceAnyToInterface(desc.CalendarNames), State: plugin.StateIsSet}
	a.AutomationTargetParameterName = plugin.TValue[string]{Data: convert.ToValue(desc.AutomationTargetParameterName), State: plugin.StateIsSet}

	a.fetched = true
	return nil
}

func (a *mqlAwsSsmAssociation) populateEmptyDetail() {
	a.Status = plugin.TValue[any]{Data: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	a.CreatedDate = plugin.TValue[*time.Time]{Data: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	a.LastSuccessfulExecutionDate = plugin.TValue[*time.Time]{Data: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	a.ComplianceSeverity = plugin.TValue[string]{Data: "", State: plugin.StateIsSet | plugin.StateIsNull}
	a.SyncCompliance = plugin.TValue[string]{Data: "", State: plugin.StateIsSet | plugin.StateIsNull}
	a.ApplyOnlyAtCronInterval = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet | plugin.StateIsNull}
	a.MaxConcurrency = plugin.TValue[string]{Data: "", State: plugin.StateIsSet | plugin.StateIsNull}
	a.MaxErrors = plugin.TValue[string]{Data: "", State: plugin.StateIsSet | plugin.StateIsNull}
	a.LastUpdatedAt = plugin.TValue[*time.Time]{Data: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	a.CalendarNames = plugin.TValue[[]any]{Data: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	a.AutomationTargetParameterName = plugin.TValue[string]{Data: "", State: plugin.StateIsSet | plugin.StateIsNull}
}

func (a *mqlAwsSsmAssociation) status() (any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsSsmAssociation) createdDate() (*time.Time, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsSsmAssociation) lastSuccessfulExecutionDate() (*time.Time, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsSsmAssociation) complianceSeverity() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsSsmAssociation) syncCompliance() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsSsmAssociation) applyOnlyAtCronInterval() (bool, error) {
	return false, a.fetchDetail()
}

func (a *mqlAwsSsmAssociation) maxConcurrency() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsSsmAssociation) maxErrors() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsSsmAssociation) lastUpdatedAt() (*time.Time, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsSsmAssociation) calendarNames() ([]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsSsmAssociation) automationTargetParameterName() (string, error) {
	return "", a.fetchDetail()
}

// ---------------- Service settings ----------------

// ssmServiceSettingIds is the fixed list of SSM service settings we inspect for
// posture audits. These cover document public-sharing, Session Manager logging
// destinations, Parameter Store tier defaults, and managed-instance activation.
var ssmServiceSettingIds = []string{
	"/ssm/documents/console/public-sharing-permission",
	"/ssm/managed-instance/activation-tier",
	"/ssm/managed-instance/default-ec2-instance-management-role",
	"/ssm/automation/customer-script-log-destination",
	"/ssm/automation/customer-script-log-group-name",
	"/ssm/parameter-store/default-parameter-tier",
	"/ssm/parameter-store/high-throughput-enabled",
	"/ssm/opsinsights/opscenter",
	"/ssm/appmanager/appmanager-enabled",
}

func (a *mqlAwsSsm) serviceSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getServiceSettings(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSsm) getServiceSettings(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			res := []any{}
			ssmsvc := conn.Ssm(region)
			ctx := context.Background()

			for _, settingId := range ssmServiceSettingIds {
				id := settingId
				resp, err := ssmsvc.GetServiceSetting(ctx, &ssm.GetServiceSettingInput{
					SettingId: &id,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Str("settingId", id).Msg("access denied reading SSM service setting")
						continue
					}
					return nil, errors.Wrapf(err, "could not read ssm service setting %q", id)
				}
				if resp == nil || resp.ServiceSetting == nil {
					continue
				}
				s := resp.ServiceSetting

				mqlSetting, err := CreateResource(a.MqlRuntime, "aws.ssm.serviceSetting",
					map[string]*llx.RawData{
						"settingId":        llx.StringData(id),
						"region":           llx.StringData(region),
						"settingValue":     llx.StringDataPtr(s.SettingValue),
						"status":           llx.StringDataPtr(s.Status),
						"arn":              llx.StringDataPtr(s.ARN),
						"lastModifiedDate": llx.TimeDataPtr(s.LastModifiedDate),
						"lastModifiedUser": llx.StringDataPtr(s.LastModifiedUser),
					})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlSetting)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsSsmServiceSetting) id() (string, error) {
	return a.Region.Data + "/" + a.SettingId.Data, nil
}

func initAwsSsmServiceSetting(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) == 0 {
		return args, nil, nil
	}
	settingIdArg, ok := args["settingId"]
	if !ok || settingIdArg == nil {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	region := conn.Region()
	if r, ok := args["region"]; ok && r != nil {
		region = r.Value.(string)
	}
	ssmsvc := conn.Ssm(region)
	settingId := settingIdArg.Value.(string)

	resp, err := ssmsvc.GetServiceSetting(context.Background(), &ssm.GetServiceSettingInput{
		SettingId: &settingId,
	})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.ServiceSetting == nil {
		return nil, nil, errors.New("service setting not found: " + settingId)
	}
	s := resp.ServiceSetting

	args["settingId"] = llx.StringData(settingId)
	args["region"] = llx.StringData(region)
	args["settingValue"] = llx.StringDataPtr(s.SettingValue)
	args["status"] = llx.StringDataPtr(s.Status)
	args["arn"] = llx.StringDataPtr(s.ARN)
	args["lastModifiedDate"] = llx.TimeDataPtr(s.LastModifiedDate)
	args["lastModifiedUser"] = llx.StringDataPtr(s.LastModifiedUser)
	return args, nil, nil
}

// ---------------- Session Manager preferences ----------------

const ssmSessionManagerPreferencesDoc = "SSM-SessionManagerRunShell"

func (a *mqlAwsSsm) sessionManagerPreferences() (any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	// The Session Manager preferences document is global to the account but
	// stored per-region. Query the default region to keep this single-shot.
	region := conn.Region()
	ssmsvc := conn.Ssm(region)
	ctx := context.Background()

	name := ssmSessionManagerPreferencesDoc
	resp, err := ssmsvc.GetDocument(ctx, &ssm.GetDocumentInput{
		Name: &name,
	})
	if err != nil {
		if isSsmDocumentNotFound(err) {
			return nil, nil
		}
		if Is400AccessDeniedError(err) {
			log.Warn().Str("region", region).Str("document", name).Msg("access denied reading SSM Session Manager preferences document")
			return nil, nil
		}
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	return map[string]any{
		"name":            convert.ToValue(resp.Name),
		"documentVersion": convert.ToValue(resp.DocumentVersion),
		"documentFormat":  string(resp.DocumentFormat),
		"documentType":    string(resp.DocumentType),
		"status":          string(resp.Status),
		"content":         convert.ToValue(resp.Content),
	}, nil
}

func isSsmDocumentNotFound(err error) bool {
	var notFound *types.InvalidDocument
	if errors.As(err, &notFound) {
		return true
	}
	return false
}
