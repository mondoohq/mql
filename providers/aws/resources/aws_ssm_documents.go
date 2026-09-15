// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
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

func (a *mqlAwsSsm) documents() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDocuments(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

const ssmDocumentArnPattern = "arn:aws:ssm:%s:%s:document/%s"

func (a *mqlAwsSsm) getDocuments(conn *connection.AwsConnection) []*jobpool.Job {
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

			// Only list documents owned by the account
			input := &ssm.ListDocumentsInput{
				Filters: []types.DocumentKeyValuesFilter{
					{
						Key:    aws.String("Owner"),
						Values: []string{"Self"},
					},
				},
			}
			paginator := ssm.NewListDocumentsPaginator(ssmsvc, input)
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather ssm documents")
				}

				for _, doc := range resp.DocumentIdentifiers {
					platformTypes := make([]any, 0, len(doc.PlatformTypes))
					for _, pt := range doc.PlatformTypes {
						platformTypes = append(platformTypes, string(pt))
					}

					tags := ssmTagsToMap(doc.Tags)
					arn := fmt.Sprintf(ssmDocumentArnPattern, region, conn.AccountId(), convert.ToValue(doc.Name))

					mqlDoc, err := CreateResource(a.MqlRuntime, "aws.ssm.document",
						map[string]*llx.RawData{
							"arn":             llx.StringData(arn),
							"name":            llx.StringDataPtr(doc.Name),
							"region":          llx.StringData(region),
							"documentType":    llx.StringData(string(doc.DocumentType)),
							"documentFormat":  llx.StringData(string(doc.DocumentFormat)),
							"documentVersion": llx.StringDataPtr(doc.DocumentVersion),
							"owner":           llx.StringDataPtr(doc.Owner),
							"platformTypes":   llx.ArrayData(platformTypes, mqlTypes.String),
							"tags":            llx.MapData(toInterfaceMap(tags), mqlTypes.String),
							"reviewStatus":    llx.StringData(string(doc.ReviewStatus)),
							"createdAt":       llx.TimeDataPtr(doc.CreatedDate),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlDoc)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSsmDocumentInternal struct {
	detailFetched  bool
	contentFetched bool
	detailLock     sync.Mutex
	contentLock    sync.Mutex
}

func (a *mqlAwsSsmDocument) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSsmDocument) fetchDetail() error {
	if a.detailFetched {
		return nil
	}
	a.detailLock.Lock()
	defer a.detailLock.Unlock()
	if a.detailFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ssmsvc := conn.Ssm(a.Region.Data)
	ctx := context.Background()

	name := a.Name.Data
	resp, err := ssmsvc.DescribeDocument(ctx, &ssm.DescribeDocumentInput{
		Name: &name,
	})
	if err != nil {
		return err
	}
	if resp.Document != nil {
		a.Description = plugin.TValue[string]{Data: convert.ToValue(resp.Document.Description), State: plugin.StateIsSet}
		a.Status = plugin.TValue[string]{Data: string(resp.Document.Status), State: plugin.StateIsSet}
	} else {
		a.Description = plugin.TValue[string]{Data: "", State: plugin.StateIsSet}
		a.Status = plugin.TValue[string]{Data: "", State: plugin.StateIsSet}
	}

	a.detailFetched = true
	return nil
}

func (a *mqlAwsSsmDocument) description() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsSsmDocument) status() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsSsmDocument) content() (string, error) {
	if a.contentFetched {
		return a.Content.Data, nil
	}
	a.contentLock.Lock()
	defer a.contentLock.Unlock()
	if a.contentFetched {
		return a.Content.Data, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ssmsvc := conn.Ssm(a.Region.Data)
	ctx := context.Background()

	name := a.Name.Data
	resp, err := ssmsvc.GetDocument(ctx, &ssm.GetDocumentInput{
		Name: &name,
	})
	if err != nil {
		return "", err
	}

	a.Content = plugin.TValue[string]{Data: convert.ToValue(resp.Content), State: plugin.StateIsSet}
	a.contentFetched = true
	return a.Content.Data, nil
}

func (a *mqlAwsSsmDocument) permissions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	ssmsvc := conn.Ssm(region)
	ctx := context.Background()

	name := a.Name.Data
	resp, err := ssmsvc.DescribeDocumentPermission(ctx, &ssm.DescribeDocumentPermissionInput{
		Name:           &name,
		PermissionType: types.DocumentPermissionTypeShare,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, nil
		}
		return nil, err
	}

	res := []any{}
	for _, acctId := range resp.AccountIds {
		res = append(res, map[string]any{
			"accountId": acctId,
			"type":      "Share",
		})
	}
	for _, sharing := range resp.AccountSharingInfoList {
		res = append(res, map[string]any{
			"accountId":     convert.ToValue(sharing.AccountId),
			"sharedVersion": convert.ToValue(sharing.SharedDocumentVersion),
		})
	}
	return res, nil
}

func ssmTagsToMap(tags []types.Tag) map[string]string {
	return tagsToStringMap(tags, func(t types.Tag) *string { return t.Key }, func(t types.Tag) *string { return t.Value })
}

func (a *mqlAwsSsm) patchBaselines() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getPatchBaselines(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

const ssmPatchBaselineArnPattern = "arn:aws:ssm:%s:%s:patchbaseline/%s"

// ssmPatchBaselineArn builds the ARN for a patch baseline.
//
// AWS-managed baselines - the ones every account has, and which an unfiltered
// DescribePatchBaselines returns - report their BaselineId as a full ARN owned by
// an AWS service account, not as a bare pb-* id. Wrapping that in the pattern
// produced a doubled ARN that also claimed the caller's account owned an
// AWS-owned baseline, and since id() returns Arn.Data it became the cache key
// too. GetPatchBaseline documents the full ARN as the correct input for these,
// so pass it through untouched.
func ssmPatchBaselineArn(region, accountID, baselineID string) string {
	if strings.HasPrefix(baselineID, "arn:") {
		return baselineID
	}
	return fmt.Sprintf(ssmPatchBaselineArnPattern, region, accountID, baselineID)
}

func (a *mqlAwsSsm) getPatchBaselines(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := ssm.NewDescribePatchBaselinesPaginator(ssmsvc, &ssm.DescribePatchBaselinesInput{})
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather ssm patch baselines")
				}

				for _, pb := range resp.BaselineIdentities {
					arn := ssmPatchBaselineArn(region, conn.AccountId(), convert.ToValue(pb.BaselineId))

					mqlPB, err := CreateResource(a.MqlRuntime, "aws.ssm.patchBaseline",
						map[string]*llx.RawData{
							"id":              llx.StringDataPtr(pb.BaselineId),
							"arn":             llx.StringData(arn),
							"name":            llx.StringDataPtr(pb.BaselineName),
							"region":          llx.StringData(region),
							"description":     llx.StringDataPtr(pb.BaselineDescription),
							"operatingSystem": llx.StringData(string(pb.OperatingSystem)),
							"isDefault":       llx.BoolData(pb.DefaultBaseline),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPB)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSsmPatchBaselineInternal struct {
	fetched  bool
	fetchErr error
	lock     sync.Mutex
}

func (a *mqlAwsSsmPatchBaseline) id() (string, error) {
	return a.Arn.Data, nil
}

// ssmPatchApprovalRules maps a baseline's approval rules into dicts.
//
// Every value has to be JSON-native: dict2primitive rejects a *int32 or a
// *bool outright, so leaving the SDK pointers in place fails the whole field
// at query time rather than degrading it.
func ssmPatchApprovalRules(rules *types.PatchRuleGroup) []any {
	approvalRules := []any{}
	if rules == nil {
		return approvalRules
	}
	for _, rule := range rules.PatchRules {
		patchFilters := []any{}
		if rule.PatchFilterGroup != nil {
			for _, pf := range rule.PatchFilterGroup.PatchFilters {
				vals := make([]any, 0, len(pf.Values))
				for _, v := range pf.Values {
					vals = append(vals, v)
				}
				patchFilters = append(patchFilters, map[string]any{
					"key":    string(pf.Key),
					"values": vals,
				})
			}
		}
		approvalRules = append(approvalRules, map[string]any{
			"approveAfterDays":  int64(convert.ToValue(rule.ApproveAfterDays)),
			"complianceLevel":   string(rule.ComplianceLevel),
			"enableNonSecurity": convert.ToValue(rule.EnableNonSecurity),
			"patchFilters":      patchFilters,
		})
	}
	return approvalRules
}

func (a *mqlAwsSsmPatchBaseline) fetchDetails() error {
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

	baselineId := a.Id.Data
	resp, err := ssmsvc.GetPatchBaseline(ctx, &ssm.GetPatchBaselineInput{
		BaselineId: &baselineId,
	})
	if err != nil {
		a.fetched = true
		a.fetchErr = err
		return err
	}

	approvalRules := ssmPatchApprovalRules(resp.ApprovalRules)

	// Global filters
	globalFilters := []any{}
	if resp.GlobalFilters != nil {
		for _, pf := range resp.GlobalFilters.PatchFilters {
			vals := make([]any, 0, len(pf.Values))
			for _, v := range pf.Values {
				vals = append(vals, v)
			}
			globalFilters = append(globalFilters, map[string]any{
				"key":    string(pf.Key),
				"values": vals,
			})
		}
	}

	// Sources
	sources := []any{}
	for _, src := range resp.Sources {
		products := make([]any, 0, len(src.Products))
		for _, p := range src.Products {
			products = append(products, p)
		}
		sources = append(sources, map[string]any{
			"name":          convert.ToValue(src.Name),
			"products":      products,
			"configuration": convert.ToValue(src.Configuration),
		})
	}

	a.ApprovalRules = plugin.TValue[[]any]{Data: approvalRules, State: plugin.StateIsSet}
	a.ApprovedPatches = plugin.TValue[[]any]{Data: convert.SliceAnyToInterface(resp.ApprovedPatches), State: plugin.StateIsSet}
	a.ApprovedPatchesComplianceLevel = plugin.TValue[string]{Data: string(resp.ApprovedPatchesComplianceLevel), State: plugin.StateIsSet}
	a.RejectedPatches = plugin.TValue[[]any]{Data: convert.SliceAnyToInterface(resp.RejectedPatches), State: plugin.StateIsSet}
	a.RejectedPatchesAction = plugin.TValue[string]{Data: string(resp.RejectedPatchesAction), State: plugin.StateIsSet}
	a.GlobalFilters = plugin.TValue[[]any]{Data: globalFilters, State: plugin.StateIsSet}
	a.Sources = plugin.TValue[[]any]{Data: sources, State: plugin.StateIsSet}
	a.CreatedAt = plugin.TValue[*time.Time]{Data: resp.CreatedDate, State: plugin.StateIsSet}
	a.ModifiedAt = plugin.TValue[*time.Time]{Data: resp.ModifiedDate, State: plugin.StateIsSet}
	a.ApprovedPatchesEnableNonSecurity = plugin.TValue[bool]{Data: convert.ToValue(resp.ApprovedPatchesEnableNonSecurity), State: plugin.StateIsSet}
	a.AvailableSecurityUpdatesComplianceStatus = plugin.TValue[string]{Data: string(resp.AvailableSecurityUpdatesComplianceStatus), State: plugin.StateIsSet}

	a.fetched = true
	return nil
}

func (a *mqlAwsSsmPatchBaseline) approvalRules() ([]any, error) {
	return nil, a.fetchDetails()
}

func (a *mqlAwsSsmPatchBaseline) approvedPatches() ([]any, error) {
	return nil, a.fetchDetails()
}

func (a *mqlAwsSsmPatchBaseline) approvedPatchesComplianceLevel() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsSsmPatchBaseline) rejectedPatches() ([]any, error) {
	return nil, a.fetchDetails()
}

func (a *mqlAwsSsmPatchBaseline) rejectedPatchesAction() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsSsmPatchBaseline) globalFilters() ([]any, error) {
	return nil, a.fetchDetails()
}

func (a *mqlAwsSsmPatchBaseline) sources() ([]any, error) {
	return nil, a.fetchDetails()
}

func (a *mqlAwsSsmPatchBaseline) createdAt() (*time.Time, error) {
	return nil, a.fetchDetails()
}

func (a *mqlAwsSsmPatchBaseline) modifiedAt() (*time.Time, error) {
	return nil, a.fetchDetails()
}

func (a *mqlAwsSsmPatchBaseline) approvedPatchesEnableNonSecurity() (bool, error) {
	return false, a.fetchDetails()
}

func (a *mqlAwsSsmPatchBaseline) availableSecurityUpdatesComplianceStatus() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsSsmPatchBaseline) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ssmsvc := conn.Ssm(a.Region.Data)
	ctx := context.Background()

	baselineId := a.Id.Data
	resp, err := ssmsvc.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{
		ResourceType: types.ResourceTypeForTaggingPatchBaseline,
		ResourceId:   &baselineId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return markTagsUnreadable(&a.Tags)
		}
		return nil, err
	}
	return toInterfaceMap(ssmTagsToMap(resp.TagList)), nil
}

func (a *mqlAwsSsm) maintenanceWindows() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getMaintenanceWindows(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

const ssmMaintenanceWindowArnPattern = "arn:aws:ssm:%s:%s:maintenancewindow/%s"

func (a *mqlAwsSsm) getMaintenanceWindows(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := ssm.NewDescribeMaintenanceWindowsPaginator(ssmsvc, &ssm.DescribeMaintenanceWindowsInput{})
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather ssm maintenance windows")
				}

				for _, mw := range resp.WindowIdentities {
					arn := fmt.Sprintf(ssmMaintenanceWindowArnPattern, region, conn.AccountId(), convert.ToValue(mw.WindowId))

					var scheduleOffset int64
					if mw.ScheduleOffset != nil {
						scheduleOffset = int64(*mw.ScheduleOffset)
					}

					mqlMW, err := CreateResource(a.MqlRuntime, "aws.ssm.maintenanceWindow",
						map[string]*llx.RawData{
							"id":                llx.StringDataPtr(mw.WindowId),
							"arn":               llx.StringData(arn),
							"name":              llx.StringDataPtr(mw.Name),
							"region":            llx.StringData(region),
							"description":       llx.StringDataPtr(mw.Description),
							"enabled":           llx.BoolData(mw.Enabled),
							"schedule":          llx.StringDataPtr(mw.Schedule),
							"scheduleTimezone":  llx.StringDataPtr(mw.ScheduleTimezone),
							"scheduleOffset":    llx.IntData(scheduleOffset),
							"duration":          llx.IntData(int64(convert.ToValue(mw.Duration))),
							"cutoff":            llx.IntData(int64(mw.Cutoff)),
							"startDate":         llx.TimeData(parseTimeOrZero(mw.StartDate)),
							"endDate":           llx.TimeData(parseTimeOrZero(mw.EndDate)),
							"nextExecutionTime": llx.TimeData(parseTimeOrZero(mw.NextExecutionTime)),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlMW)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsSsmMaintenanceWindow) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSsmMaintenanceWindow) allowUnassociatedTargets() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	return detail.AllowUnassociatedTargets, nil
}

func (a *mqlAwsSsmMaintenanceWindow) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ssmsvc := conn.Ssm(a.Region.Data)
	ctx := context.Background()

	windowId := a.Id.Data
	resp, err := ssmsvc.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{
		ResourceType: types.ResourceTypeForTaggingMaintenanceWindow,
		ResourceId:   &windowId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return markTagsUnreadable(&a.Tags)
		}
		return nil, err
	}
	return toInterfaceMap(ssmTagsToMap(resp.TagList)), nil
}

func (a *mqlAwsSsm) associations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAssociations(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSsm) getAssociations(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := ssm.NewListAssociationsPaginator(ssmsvc, &ssm.ListAssociationsInput{})
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather ssm associations")
				}

				for _, assoc := range resp.Associations {
					targets := assocTargetsToDict(assoc.Targets)

					var overview map[string]any
					if assoc.Overview != nil {
						statusCounts := make(map[string]any)
						for k, v := range assoc.Overview.AssociationStatusAggregatedCount {
							statusCounts[k] = v
						}
						overview = map[string]any{
							"status":         convert.ToValue(assoc.Overview.Status),
							"detailedStatus": convert.ToValue(assoc.Overview.DetailedStatus),
							"statusCounts":   statusCounts,
						}
					}

					assocId := convert.ToValue(assoc.AssociationId)
					mqlAssoc, err := CreateResource(a.MqlRuntime, "aws.ssm.association",
						map[string]*llx.RawData{
							"associationId":     llx.StringData(assocId),
							"name":              llx.StringDataPtr(assoc.Name),
							"associationName":   llx.StringDataPtr(assoc.AssociationName),
							"region":            llx.StringData(region),
							"documentVersion":   llx.StringDataPtr(assoc.DocumentVersion),
							"instanceId":        llx.StringDataPtr(assoc.InstanceId),
							"targets":           llx.ArrayData(targets, mqlTypes.Dict),
							"schedule":          llx.StringDataPtr(assoc.ScheduleExpression),
							"lastExecutionDate": llx.TimeDataPtr(assoc.LastExecutionDate),
							"overview":          llx.DictData(overview),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlAssoc)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func assocTargetsToDict(in []types.Target) []any {
	targets := []any{}
	for _, t := range in {
		vals := make([]any, 0, len(t.Values))
		for _, v := range t.Values {
			vals = append(vals, v)
		}
		targets = append(targets, map[string]any{
			"key":    convert.ToValue(t.Key),
			"values": vals,
		})
	}
	return targets
}

func (a *mqlAwsSsmAssociation) id() (string, error) {
	return a.Region.Data + "/" + a.AssociationId.Data, nil
}

func severitySummaryToDict(s *types.SeveritySummary) map[string]any {
	if s == nil {
		return nil
	}
	return map[string]any{
		"criticalCount":      int64(s.CriticalCount),
		"highCount":          int64(s.HighCount),
		"mediumCount":        int64(s.MediumCount),
		"lowCount":           int64(s.LowCount),
		"informationalCount": int64(s.InformationalCount),
		"unspecifiedCount":   int64(s.UnspecifiedCount),
	}
}

func (a *mqlAwsSsm) complianceSummaries() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getComplianceSummaries(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSsm) getComplianceSummaries(conn *connection.AwsConnection) []*jobpool.Job {
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

			var nextToken *string
			for {
				resp, err := ssmsvc.ListResourceComplianceSummaries(ctx, &ssm.ListResourceComplianceSummariesInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather ssm compliance summaries")
				}

				for _, item := range resp.ResourceComplianceSummaryItems {
					var compliantCount, nonCompliantCount int64
					var compliantSeverity, nonCompliantSeverity map[string]any
					if item.CompliantSummary != nil {
						compliantCount = int64(item.CompliantSummary.CompliantCount)
						compliantSeverity = severitySummaryToDict(item.CompliantSummary.SeveritySummary)
					}
					if item.NonCompliantSummary != nil {
						nonCompliantCount = int64(item.NonCompliantSummary.NonCompliantCount)
						nonCompliantSeverity = severitySummaryToDict(item.NonCompliantSummary.SeveritySummary)
					}

					var execSummary map[string]any
					if item.ExecutionSummary != nil {
						execSummary = map[string]any{
							"executionTime": convert.ToValue(item.ExecutionSummary.ExecutionTime).String(),
							"executionId":   convert.ToValue(item.ExecutionSummary.ExecutionId),
							"executionType": convert.ToValue(item.ExecutionSummary.ExecutionType),
						}
					}

					mqlItem, err := CreateResource(a.MqlRuntime, "aws.ssm.complianceSummary",
						map[string]*llx.RawData{
							"complianceType":              llx.StringDataPtr(item.ComplianceType),
							"resourceId":                  llx.StringDataPtr(item.ResourceId),
							"resourceType":                llx.StringDataPtr(item.ResourceType),
							"region":                      llx.StringData(region),
							"status":                      llx.StringData(string(item.Status)),
							"compliantCount":              llx.IntData(compliantCount),
							"nonCompliantCount":           llx.IntData(nonCompliantCount),
							"overallSeverity":             llx.StringData(string(item.OverallSeverity)),
							"compliantSeveritySummary":    llx.DictData(compliantSeverity),
							"nonCompliantSeveritySummary": llx.DictData(nonCompliantSeverity),
							"executionSummary":            llx.DictData(execSummary),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlItem)
				}

				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsSsmComplianceSummary) id() (string, error) {
	return a.Region.Data + "/" + a.ResourceId.Data + "/" + a.ComplianceType.Data, nil
}
